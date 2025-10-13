cmake_minimum_required(VERSION 3.5)

# Set extension name here
set(TARGET_NAME boilstream)

# DuckDB provides mbedTLS for all platforms (including WASM)
# We use duckdb_mbedtls::MbedTlsWrapper for cryptographic operations
# OpenSSL is NOT needed - removed to support WASM builds

set(EXTENSION_NAME ${TARGET_NAME}_extension)
set(LOADABLE_EXTENSION_NAME ${TARGET_NAME}_loadable_extension)

project(${TARGET_NAME})
include_directories(src/include)

# Build the Rust OPAQUE client library
include(ExternalProject)

# Check if we're building for WASM
set(IS_WASM_BUILD OFF)
if(EMSCRIPTEN OR CMAKE_SYSTEM_NAME STREQUAL "Emscripten")
    set(IS_WASM_BUILD ON)
    message(STATUS "Detected WASM build with Emscripten")
endif()

# Determine the build profile and target directory
if(CMAKE_BUILD_TYPE MATCHES "Debug")
    set(RUST_BUILD_FLAG "")
    set(RUST_PROFILE "debug")
else()
    set(RUST_BUILD_FLAG "--release")
    set(RUST_PROFILE "release")
endif()

# Configure Rust target and library name based on platform
if(IS_WASM_BUILD)
    # WASM build: target wasm32-unknown-emscripten
    # Use staticlib with C FFI functions
    set(RUST_TARGET "wasm32-unknown-emscripten")
    set(RUST_TARGET_FLAG "--target=${RUST_TARGET}")
    set(RUST_TARGET_DIR "${CMAKE_CURRENT_SOURCE_DIR}/opaque-client/target/${RUST_TARGET}/${RUST_PROFILE}")
    set(RUST_LIB_NAME "libopaque_client.a")
    message(STATUS "Building Rust for WASM target: ${RUST_TARGET}")
else()
    # Native build - check for macOS architecture from GitHub Actions
    set(RUST_TARGET_FLAG "")
    set(RUST_TARGET_DIR "${CMAKE_CURRENT_SOURCE_DIR}/opaque-client/target/${RUST_PROFILE}")

    if(APPLE AND DEFINED ENV{OSX_BUILD_ARCH})
        # GitHub Actions sets OSX_BUILD_ARCH for cross-compilation
        if($ENV{OSX_BUILD_ARCH} STREQUAL "x86_64")
            set(RUST_TARGET "x86_64-apple-darwin")
            set(RUST_TARGET_FLAG "--target=${RUST_TARGET}")
            set(RUST_TARGET_DIR "${CMAKE_CURRENT_SOURCE_DIR}/opaque-client/target/${RUST_TARGET}/${RUST_PROFILE}")
            message(STATUS "Building Rust for macOS x86_64 (OSX_BUILD_ARCH=$ENV{OSX_BUILD_ARCH})")
        elseif($ENV{OSX_BUILD_ARCH} STREQUAL "arm64")
            set(RUST_TARGET "aarch64-apple-darwin")
            set(RUST_TARGET_FLAG "--target=${RUST_TARGET}")
            set(RUST_TARGET_DIR "${CMAKE_CURRENT_SOURCE_DIR}/opaque-client/target/${RUST_TARGET}/${RUST_PROFILE}")
            message(STATUS "Building Rust for macOS ARM64 (OSX_BUILD_ARCH=$ENV{OSX_BUILD_ARCH})")
        endif()
    else()
        message(STATUS "Building Rust for native platform")
    endif()

    if(WIN32)
        set(RUST_LIB_NAME "opaque_client.lib")
    elseif(APPLE)
        set(RUST_LIB_NAME "libopaque_client.a")
    else()
        set(RUST_LIB_NAME "libopaque_client.a")
    endif()
endif()

set(RUST_LIB_PATH "${RUST_TARGET_DIR}/${RUST_LIB_NAME}")

# Add custom command to build the Rust library
add_custom_command(
    OUTPUT ${RUST_LIB_PATH}
    COMMAND cargo build ${RUST_BUILD_FLAG} ${RUST_TARGET_FLAG}
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/opaque-client
    COMMENT "Building Rust OPAQUE client library"
    VERBATIM
)

# Create a custom target that depends on the Rust library
add_custom_target(rust_opaque_client ALL DEPENDS ${RUST_LIB_PATH})

# Create an imported library target for the Rust library
add_library(opaque_client_rust STATIC IMPORTED GLOBAL)
set_target_properties(opaque_client_rust PROPERTIES
    IMPORTED_LOCATION ${RUST_LIB_PATH}
)
add_dependencies(opaque_client_rust rust_opaque_client)

set(EXTENSION_SOURCES src/boilstream_extension.cpp src/boilstream_secret_storage.cpp src/opaque_wrapper.cpp)

build_static_extension(${TARGET_NAME} ${EXTENSION_SOURCES})
build_loadable_extension(${TARGET_NAME} " " ${EXTENSION_SOURCES})

# # Enable debug logging for OPAQUE authentication flows
# target_compile_definitions(${EXTENSION_NAME} PRIVATE BOILSTREAM_DEBUG)
# target_compile_definitions(${LOADABLE_EXTENSION_NAME} PRIVATE BOILSTREAM_DEBUG)

# Link Rust OPAQUE client library in both the static library as the loadable extension
# Note: We use duckdb_mbedtls (provided by DuckDB) instead of OpenSSL
target_link_libraries(${EXTENSION_NAME} opaque_client_rust)
target_link_libraries(${LOADABLE_EXTENSION_NAME} opaque_client_rust)

# On macOS, force load the Rust library to ensure all symbols are included
if(APPLE)
    target_link_options(${EXTENSION_NAME} PRIVATE "-Wl,-force_load,${RUST_LIB_PATH}")
    target_link_options(${LOADABLE_EXTENSION_NAME} PRIVATE "-Wl,-force_load,${RUST_LIB_PATH}")
endif()

# On some platforms, we need to link additional system libraries for Rust
if(IS_WASM_BUILD)
    # WASM doesn't need additional system libraries - everything is handled by Emscripten
    message(STATUS "WASM build: skipping platform-specific library linking")
elseif(UNIX AND NOT APPLE)
    target_link_libraries(${EXTENSION_NAME} dl pthread)
    target_link_libraries(${LOADABLE_EXTENSION_NAME} dl pthread)
elseif(APPLE)
    # macOS requires additional frameworks and libraries for Rust
    target_link_libraries(${EXTENSION_NAME} "-framework Security" "-framework Foundation" "-framework CoreFoundation" resolv)
    target_link_libraries(${LOADABLE_EXTENSION_NAME} "-framework Security" "-framework Foundation" "-framework CoreFoundation" resolv)
elseif(WIN32)
    target_link_libraries(${EXTENSION_NAME} ws2_32 userenv bcrypt)
    target_link_libraries(${LOADABLE_EXTENSION_NAME} ws2_32 userenv bcrypt)
endif()

install(
  TARGETS ${EXTENSION_NAME}
  EXPORT "${DUCKDB_EXPORT_SET}"
  LIBRARY DESTINATION "${INSTALL_LIB_DIR}"
  ARCHIVE DESTINATION "${INSTALL_LIB_DIR}")
