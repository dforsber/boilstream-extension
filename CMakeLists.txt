cmake_minimum_required(VERSION 3.15...3.30)

# Set extension name here
set(TARGET_NAME boilstream)

# DuckDB provides mbedTLS for all platforms (including WASM)
# We use duckdb_mbedtls::MbedTlsWrapper for cryptographic operations
# OpenSSL is NOT needed - removed to support WASM builds

set(EXTENSION_NAME ${TARGET_NAME}_extension)
set(LOADABLE_EXTENSION_NAME ${TARGET_NAME}_loadable_extension)

project(${TARGET_NAME})
include_directories(src/include)

# Check if we're building for WASM
set(IS_WASM_BUILD OFF)
if(EMSCRIPTEN OR CMAKE_SYSTEM_NAME STREQUAL "Emscripten")
    set(IS_WASM_BUILD ON)
    message(STATUS "Detected WASM build with Emscripten")
endif()

# Build the Rust OPAQUE client library
if(IS_WASM_BUILD)
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
    set(RUST_TARGET_DIR "${CMAKE_CURRENT_SOURCE_DIR}/opaque-client/target/${RUST_TARGET}/${RUST_PROFILE}")
    set(RUST_LIB_PATH "${RUST_TARGET_DIR}/libopaque_client.a")

    add_custom_command(
        OUTPUT ${RUST_LIB_PATH}
        COMMAND cargo build ${RUST_BUILD_FLAG} --target=${RUST_TARGET}
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/opaque-client
        COMMENT "Building Rust OPAQUE client library for WASM"
        VERBATIM
    )

    add_custom_target(rust_opaque_client ALL DEPENDS ${RUST_LIB_PATH})
    add_library(opaque_client_rust STATIC IMPORTED GLOBAL)
    set_target_properties(opaque_client_rust PROPERTIES IMPORTED_LOCATION ${RUST_LIB_PATH})
    add_dependencies(opaque_client_rust rust_opaque_client)

    message(STATUS "WASM: Manual cargo build")
else()
    # Native build: Use Corrosion
    include(FetchContent)
    FetchContent_Declare(
        Corrosion
        GIT_REPOSITORY https://github.com/corrosion-rs/corrosion.git
        GIT_TAG v0.5.2
    )
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
        MANIFEST_PATH "${CMAKE_CURRENT_SOURCE_DIR}/opaque-client/Cargo.toml"
    )

    # Use the exact target name Corrosion creates from Cargo.toml package name
    # Package "opaque-client" with crate-type "staticlib" creates "opaque_client-static"
    # (Corrosion converts hyphens to underscores for target names)
    add_library(opaque_client_rust ALIAS opaque_client-static)

    message(STATUS "Corrosion: Auto-linking Rust dependencies")
endif()

set(EXTENSION_SOURCES src/boilstream_extension.cpp src/boilstream_secret_storage.cpp src/opaque_wrapper.cpp)

build_static_extension(${TARGET_NAME} ${EXTENSION_SOURCES})
build_loadable_extension(${TARGET_NAME} " " ${EXTENSION_SOURCES})

# # Enable debug logging for OPAQUE authentication flows
# target_compile_definitions(${EXTENSION_NAME} PRIVATE BOILSTREAM_DEBUG)
# target_compile_definitions(${LOADABLE_EXTENSION_NAME} PRIVATE BOILSTREAM_DEBUG)

# Link Rust OPAQUE client library
# opaque_client_rust is either:
# - WASM: imported target from manual cargo build
# - Native: alias to Corrosion's opaque_client-static target
target_link_libraries(${EXTENSION_NAME} opaque_client_rust)
target_link_libraries(${LOADABLE_EXTENSION_NAME} opaque_client_rust)

# Platform-specific configuration
if(IS_WASM_BUILD)
    # WASM: Skip wasm-opt to avoid --enable-bulk-memory-opt compatibility issues
    # Use -O1 for basic optimizations without wasm-opt (newer Emscripten removed this flag)
    target_link_options(${EXTENSION_NAME} PRIVATE "-O1")
    target_link_options(${LOADABLE_EXTENSION_NAME} PRIVATE "-O1")
    message(STATUS "WASM: Using -O1 link flags to skip wasm-opt")
elseif(APPLE)
    # macOS frameworks for Rust
    target_link_libraries(${EXTENSION_NAME} "-framework Security" "-framework Foundation" "-framework CoreFoundation" resolv)
    target_link_libraries(${LOADABLE_EXTENSION_NAME} "-framework Security" "-framework Foundation" "-framework CoreFoundation" resolv)
elseif(UNIX)
    # Linux system libraries
    target_link_libraries(${EXTENSION_NAME} dl pthread)
    target_link_libraries(${LOADABLE_EXTENSION_NAME} dl pthread)
elseif(WIN32)
    # Windows: Corrosion handles most dependencies, but we need to add bcrypt explicitly
    # bcrypt is needed by the getrandom crate (BCryptGenRandom function)
    target_link_libraries(${EXTENSION_NAME} bcrypt)
    target_link_libraries(${LOADABLE_EXTENSION_NAME} bcrypt)
endif()

install(
  TARGETS ${EXTENSION_NAME}
  EXPORT "${DUCKDB_EXPORT_SET}"
  LIBRARY DESTINATION "${INSTALL_LIB_DIR}"
  ARCHIVE DESTINATION "${INSTALL_LIB_DIR}")
