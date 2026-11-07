cmake_minimum_required(VERSION 3.15...3.30)

# Set extension name here
set(TARGET_NAME boilstream)

# DuckDB provides mbedTLS for all platforms (including WASM) We use
# duckdb_mbedtls::MbedTlsWrapper for cryptographic operations OpenSSL is NOT
# needed - removed to support WASM builds

set(EXTENSION_NAME ${TARGET_NAME}_extension)
set(LOADABLE_EXTENSION_NAME ${TARGET_NAME}_loadable_extension)

project(${TARGET_NAME})

# Set C++ standard to match a5 extension (proven working with WASM)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include_directories(src/include)

# Check if we're building for WASM
set(IS_WASM_BUILD OFF)
if(EMSCRIPTEN OR CMAKE_SYSTEM_NAME STREQUAL "Emscripten")
  set(IS_WASM_BUILD ON)
  message(STATUS "Detected WASM build with Emscripten")

  # Add WASM-specific compile definitions required by DuckDB extensions
  add_compile_definitions(WASM_LOADABLE_EXTENSIONS=1)

  # Both DuckDB 2.0 browser bundles use native WASM exceptions.
  add_compile_options(-fwasm-exceptions)
  add_compile_definitions(WEBDB_FAST_EXCEPTIONS=1)
  if(DEFINED ENV{WASM_BUILD_TYPE})
    if($ENV{WASM_BUILD_TYPE} STREQUAL "wasm_eh")
      message(STATUS "WASM: Using exception handling mode (wasm_eh)")
    elseif($ENV{WASM_BUILD_TYPE} STREQUAL "wasm_threads")
      add_compile_options(-pthread)
      add_compile_definitions(WITH_WASM_THREADS=1 WITH_WASM_SIMD=1
                              WITH_WASM_BULK_MEMORY=1)
      message(STATUS "WASM: Using threads mode (wasm_threads)")
    endif()
  endif()

  message(STATUS "WASM: Configured with DuckDB extension flags")
endif()

# Embedded multi-extension builds provide one shared Rust staticlib, avoiding
# duplicate OPAQUE exports and Rust runtimes. Standalone client builds keep their
# own platform-specific Cargo path below.
if(BOILSTREAM_EXTERNAL_RUST_LIB)
  if(NOT TARGET ${BOILSTREAM_EXTERNAL_RUST_LIB})
    message(FATAL_ERROR
            "External Rust library target does not exist: ${BOILSTREAM_EXTERNAL_RUST_LIB}")
  endif()
  message(STATUS
          "boilstream: Using external Rust library target '${BOILSTREAM_EXTERNAL_RUST_LIB}'")
  add_library(opaque_client_rust ALIAS ${BOILSTREAM_EXTERNAL_RUST_LIB})
elseif(IS_WASM_BUILD)
  # WASM build: Manual cargo (Corrosion doesn't support Emscripten)
  include(ExternalProject)

  if(CMAKE_BUILD_TYPE MATCHES "Debug")
    set(RUST_BUILD_FLAG "")
    set(RUST_PROFILE "debug")
  else()
    set(RUST_BUILD_FLAG "--release")
    set(RUST_PROFILE "release")
  endif()

  set(RUST_TARGET "wasm32-unknown-emscripten")
  set(RUST_TARGET_DIR
      "${CMAKE_CURRENT_BINARY_DIR}/rust/${RUST_TARGET}/${RUST_PROFILE}")
  set(RUST_LIB_PATH "${RUST_TARGET_DIR}/libopaque_client.a")
  file(READ "${CMAKE_CURRENT_SOURCE_DIR}/test/wasm/baseline.json" WASM_BASELINE)
  string(REGEX MATCH "\"rustToolchain\"[ \t]*:[ \t]*\"([^\"]+)\""
               RUST_TOOLCHAIN_MATCH "${WASM_BASELINE}")
  set(RUST_WASM_COMMAND cargo "+${CMAKE_MATCH_1}")
  set(RUST_WASM_EXTRA_ARGS "")
  if("$ENV{WASM_BUILD_TYPE}" STREQUAL "wasm_threads")
    # rustup's prebuilt std lacks atomics. Rebuild it; disabling linker feature
    # checks would produce an unsafe shared-memory module.
    string(REGEX MATCH "\"rustThreadsToolchain\"[ \t]*:[ \t]*\"([^\"]+)\""
                 RUST_TOOLCHAIN_MATCH "${WASM_BASELINE}")
    set(RUST_WASM_COMMAND
        ${CMAKE_COMMAND} -E env
        "RUSTFLAGS=-C panic=abort -C target-feature=+atomics,+bulk-memory,+mutable-globals -C link-arg=-pthread"
        cargo "+${CMAKE_MATCH_1}")
    set(RUST_WASM_EXTRA_ARGS -Zbuild-std=std,panic_abort)
  endif()

  # Let Cargo track every Rust module/build input, including future modules. A
  # CMake OUTPUT rule listing only lib.rs/registration.rs can silently retain an
  # old archive when another module changes. Cargo's own incremental check is
  # cheap and must run on every extension build (as Corrosion does natively).
  add_custom_target(
    rust_opaque_client ALL
    COMMAND
      ${RUST_WASM_COMMAND} build --locked ${RUST_WASM_EXTRA_ARGS}
      ${RUST_BUILD_FLAG} --target=${RUST_TARGET}
      --target-dir=${CMAKE_CURRENT_BINARY_DIR}/rust
    BYPRODUCTS ${RUST_LIB_PATH}
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/opaque-client
    COMMENT "Checking all Rust OPAQUE build inputs for WASM"
    VERBATIM)

  add_library(opaque_client_rust STATIC IMPORTED GLOBAL)
  set_target_properties(opaque_client_rust PROPERTIES IMPORTED_LOCATION
                                                      ${RUST_LIB_PATH})
  add_dependencies(opaque_client_rust rust_opaque_client)

  message(STATUS "WASM: Manual cargo build")
else()
  # Native build: Use Corrosion
  include(FetchContent)
  FetchContent_Declare(
    Corrosion
    GIT_REPOSITORY https://github.com/corrosion-rs/corrosion.git
    GIT_TAG v0.5.2)
  FetchContent_MakeAvailable(Corrosion)

  # Set Rust target for cross-compilation
  if(APPLE AND DEFINED ENV{OSX_BUILD_ARCH})
    if($ENV{OSX_BUILD_ARCH} STREQUAL "x86_64")
      set(Rust_CARGO_TARGET "x86_64-apple-darwin")
    elseif($ENV{OSX_BUILD_ARCH} STREQUAL "arm64")
      set(Rust_CARGO_TARGET "aarch64-apple-darwin")
    endif()
  elseif(WIN32 AND MINGW)
    set(Rust_CARGO_TARGET "x86_64-pc-windows-gnu")
  endif()

  # Import the Rust crate - creates cargo-build_opaque_client target
  corrosion_import_crate(
    MANIFEST_PATH "${CMAKE_CURRENT_SOURCE_DIR}/opaque-client/Cargo.toml" LOCKED)

  # Use the exact target name Corrosion creates from Cargo.toml package name
  # Package "opaque-client" with crate-type "staticlib" creates
  # "opaque_client-static" (Corrosion converts hyphens to underscores for target
  # names)
  add_library(opaque_client_rust ALIAS opaque_client-static)

  message(STATUS "Corrosion: Auto-linking Rust dependencies")
endif()

set(EXTENSION_SOURCES
    src/boilstream_extension.cpp src/boilstream_secret_storage.cpp
    src/boilstream_grammar.cpp src/opaque_wrapper.cpp)

build_static_extension(${TARGET_NAME} ${EXTENSION_SOURCES})
# DuckDB's WASM helper links an archive in a POST_BUILD emcc invocation;
# target_link_libraries alone does not include Rust in that final side module.
# DuckDB 2.0's runtime uses native i64 imports (WASM_BIGINT), without JS
# legalization.
if(IS_WASM_BUILD)
  set(DUCKDB_EXTENSION_BOILSTREAM_LINKED_LIBS
      "-sWASM_BIGINT=1 -fwasm-exceptions $<TARGET_FILE:opaque_client_rust>")
  if("$ENV{WASM_BUILD_TYPE}" STREQUAL "wasm_threads")
    string(APPEND DUCKDB_EXTENSION_BOILSTREAM_LINKED_LIBS " -pthread")
  endif()
endif()
build_loadable_extension(${TARGET_NAME} " " ${EXTENSION_SOURCES})
if(IS_WASM_BUILD)
  set_property(
    TARGET ${LOADABLE_EXTENSION_NAME}
    APPEND
    PROPERTY LINK_DEPENDS "$<TARGET_FILE:opaque_client_rust>")
endif()

# Enable debug logging conditionally (set -DBOILSTREAM_DEBUG=ON to enable) For
# WASM, always enable for easier browser debugging
if(BOILSTREAM_DEBUG)
  target_compile_definitions(${EXTENSION_NAME} PRIVATE BOILSTREAM_DEBUG)
  target_compile_definitions(${LOADABLE_EXTENSION_NAME}
                             PRIVATE BOILSTREAM_DEBUG)
  if(IS_WASM_BUILD)
    message(STATUS "WASM: Debug logging enabled (browser console)")
  else()
    message(STATUS "Native: Debug logging enabled (stderr)")
  endif()
endif()

# Link Rust OPAQUE client library (includes all crypto operations)
# opaque_client_rust is the client Cargo library. All cryptographic operations
# (SHA256, HMAC, HKDF, AES-GCM) are now handled by Rust
target_link_libraries(${EXTENSION_NAME} opaque_client_rust)
target_link_libraries(${LOADABLE_EXTENSION_NAME} opaque_client_rust)

# Platform-specific configuration
if(IS_WASM_BUILD)
  # WASM: Link options based on build type
  if(DEFINED ENV{WASM_BUILD_TYPE})
    if($ENV{WASM_BUILD_TYPE} STREQUAL "wasm_eh")
      target_link_options(${EXTENSION_NAME} PRIVATE "-fwasm-exceptions")
      target_link_options(${LOADABLE_EXTENSION_NAME} PRIVATE
                          "-fwasm-exceptions")
    elseif($ENV{WASM_BUILD_TYPE} STREQUAL "wasm_threads")
      target_link_options(${EXTENSION_NAME} PRIVATE "-pthread")
      target_link_options(${LOADABLE_EXTENSION_NAME} PRIVATE "-pthread")
    endif()
  endif()

  # DuckDB 2.0 exports the C++ entry point and appends the version/platform
  # metadata once. Do not re-link or relabel an intermediate archive afterward.
elseif(APPLE)
  # macOS frameworks for Rust
  target_link_libraries(
    ${EXTENSION_NAME} "-framework Security" "-framework Foundation"
    "-framework CoreFoundation" resolv)
  target_link_libraries(
    ${LOADABLE_EXTENSION_NAME} "-framework Security" "-framework Foundation"
    "-framework CoreFoundation" resolv)
elseif(UNIX)
  # Linux system libraries
  target_link_libraries(${EXTENSION_NAME} dl pthread)
  target_link_libraries(${LOADABLE_EXTENSION_NAME} dl pthread)
elseif(WIN32)
  # Windows: Corrosion handles most dependencies, but we need to add bcrypt
  # explicitly bcrypt is needed by the getrandom crate (BCryptGenRandom
  # function)
  target_link_libraries(${EXTENSION_NAME} bcrypt)
  target_link_libraries(${LOADABLE_EXTENSION_NAME} bcrypt)
endif()

install(
  TARGETS ${EXTENSION_NAME}
  EXPORT "${DUCKDB_EXPORT_SET}"
  LIBRARY DESTINATION "${INSTALL_LIB_DIR}"
  ARCHIVE DESTINATION "${INSTALL_LIB_DIR}")
