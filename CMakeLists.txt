cmake_minimum_required(VERSION 3.5)

# Set extension name here
set(TARGET_NAME boilstream)

# DuckDB's extension distribution supports vcpkg. As such, dependencies can be added in ./vcpkg.json and then
# used in cmake with find_package. Feel free to remove or replace with other dependencies.
# Note that it should also be removed from vcpkg.json to prevent needlessly installing it..
find_package(OpenSSL REQUIRED)

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
    set(RUST_TARGET "wasm32-unknown-emscripten")
    set(RUST_TARGET_FLAG "--target=${RUST_TARGET}")
    set(RUST_TARGET_DIR "${CMAKE_CURRENT_SOURCE_DIR}/opaque-client/target/${RUST_TARGET}/${RUST_PROFILE}")
    set(RUST_LIB_NAME "libopaque_client.a")
    message(STATUS "Building Rust for WASM target: ${RUST_TARGET}")
else()
    # Native build
    set(RUST_TARGET_FLAG "")
    set(RUST_TARGET_DIR "${CMAKE_CURRENT_SOURCE_DIR}/opaque-client/target/${RUST_PROFILE}")

    if(WIN32)
        set(RUST_LIB_NAME "opaque_client.lib")
    elseif(APPLE)
        set(RUST_LIB_NAME "libopaque_client.a")
    else()
        set(RUST_LIB_NAME "libopaque_client.a")
    endif()
    message(STATUS "Building Rust for native platform")
endif()

set(RUST_LIB_PATH "${RUST_TARGET_DIR}/${RUST_LIB_NAME}")

# Add custom command to build the Rust library
add_custom_command(
    OUTPUT ${RUST_LIB_PATH}
    COMMAND cargo build ${RUST_BUILD_FLAG} ${RUST_TARGET_FLAG}
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/opaque-client
    COMMENT "Building Rust OPAQUE client library for ${RUST_TARGET}"
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

# Link OpenSSL and Rust OPAQUE client library in both the static library as the loadable extension
target_link_libraries(${EXTENSION_NAME} OpenSSL::SSL OpenSSL::Crypto opaque_client_rust)
target_link_libraries(${LOADABLE_EXTENSION_NAME} OpenSSL::SSL OpenSSL::Crypto opaque_client_rust)

# On some platforms, we need to link additional system libraries for Rust
if(IS_WASM_BUILD)
    # WASM doesn't need additional system libraries - everything is handled by Emscripten
    message(STATUS "WASM build: skipping platform-specific library linking")
elseif(UNIX AND NOT APPLE)
    target_link_libraries(${EXTENSION_NAME} dl pthread)
    target_link_libraries(${LOADABLE_EXTENSION_NAME} dl pthread)
elseif(APPLE)
    target_link_libraries(${EXTENSION_NAME} "-framework Security" "-framework Foundation")
    target_link_libraries(${LOADABLE_EXTENSION_NAME} "-framework Security" "-framework Foundation")
elseif(WIN32)
    target_link_libraries(${EXTENSION_NAME} ws2_32 userenv bcrypt)
    target_link_libraries(${LOADABLE_EXTENSION_NAME} ws2_32 userenv bcrypt)
endif()

install(
  TARGETS ${EXTENSION_NAME}
  EXPORT "${DUCKDB_EXPORT_SET}"
  LIBRARY DESTINATION "${INSTALL_LIB_DIR}"
  ARCHIVE DESTINATION "${INSTALL_LIB_DIR}")
