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

    # Replace wasm-opt from emsdk 3.1.71 with version from 4.0.16
    # Use $EMSDK environment variable to find the installation
    if(DEFINED ENV{EMSDK})
        set(EMSDK_PATH "$ENV{EMSDK}")
        set(WASM_OPT_PATH "${EMSDK_PATH}/upstream/bin/wasm-opt")

        message(STATUS "WASM: Found EMSDK at ${EMSDK_PATH}")

        if(EXISTS "${WASM_OPT_PATH}" AND NOT EXISTS "${WASM_OPT_PATH}.original")
            message(STATUS "WASM: Downloading wasm-opt from Emscripten 4.0.16")

            # Download Binaryen (contains wasm-opt) from Emscripten storage
            # Emscripten 4.0.16 uses Binaryen version 124
            # Get it from the same source that emsdk uses
            set(BINARYEN_VERSION "version_124")
            set(BINARYEN_URL "https://github.com/WebAssembly/binaryen/releases/download/${BINARYEN_VERSION}/binaryen-${BINARYEN_VERSION}-x86_64-linux.tar.gz")
            set(BINARYEN_ARCHIVE "${CMAKE_CURRENT_BINARY_DIR}/binaryen.tar.gz")
            set(BINARYEN_EXTRACT_DIR "${CMAKE_CURRENT_BINARY_DIR}/binaryen-extracted")

            message(STATUS "WASM: Downloading Binaryen ${BINARYEN_VERSION}")
            file(DOWNLOAD "${BINARYEN_URL}" "${BINARYEN_ARCHIVE}"
                STATUS DOWNLOAD_STATUS
                SHOW_PROGRESS
            )

            list(GET DOWNLOAD_STATUS 0 DOWNLOAD_RESULT)
            if(DOWNLOAD_RESULT EQUAL 0)
                message(STATUS "WASM: Extracting Binaryen archive")

                # Extract the archive
                execute_process(
                    COMMAND ${CMAKE_COMMAND} -E tar xzf "${BINARYEN_ARCHIVE}"
                    WORKING_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}"
                    RESULT_VARIABLE EXTRACT_RESULT
                )

                if(EXTRACT_RESULT EQUAL 0)
                    # Find the wasm-opt binary in extracted files
                    set(NEW_WASM_OPT "${CMAKE_CURRENT_BINARY_DIR}/binaryen-${BINARYEN_VERSION}/bin/wasm-opt")

                    if(EXISTS "${NEW_WASM_OPT}")
                        # Backup original
                        execute_process(
                            COMMAND ${CMAKE_COMMAND} -E copy "${WASM_OPT_PATH}" "${WASM_OPT_PATH}.original"
                        )

                        # Replace with new version
                        execute_process(
                            COMMAND ${CMAKE_COMMAND} -E copy "${NEW_WASM_OPT}" "${WASM_OPT_PATH}"
                        )
                        execute_process(COMMAND chmod +x "${WASM_OPT_PATH}")

                        message(STATUS "WASM: Successfully replaced wasm-opt with Binaryen ${BINARYEN_VERSION}")
                    else()
                        message(WARNING "WASM: wasm-opt not found in extracted archive at ${NEW_WASM_OPT}")
                    endif()
                else()
                    message(WARNING "WASM: Failed to extract Binaryen archive")
                endif()
            else()
                message(WARNING "WASM: Failed to download Binaryen - ${DOWNLOAD_STATUS}")
            endif()
        elseif(EXISTS "${WASM_OPT_PATH}.original")
            message(STATUS "WASM: wasm-opt already replaced (backup exists)")
        else()
            message(WARNING "WASM: wasm-opt not found at expected path: ${WASM_OPT_PATH}")
        endif()
    else()
        message(WARNING "WASM: EMSDK environment variable not set")
    endif()

    message(STATUS "WASM: Configured to use updated wasm-opt")

    # FORCE override DuckDB's -O3 flags to prevent wasm-opt with deprecated flags
    # DuckDB's CMakeLists.txt sets these with APPEND, so we need FORCE to override
    set(CMAKE_CXX_FLAGS_RELEASE "-O1 -DNDEBUG" CACHE STRING "Flags used by the compiler during release builds" FORCE)
    set(CMAKE_C_FLAGS_RELEASE "-O1 -DNDEBUG" CACHE STRING "Flags used by the compiler during release builds" FORCE)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O1" CACHE STRING "General C++ flags" FORCE)
    message(STATUS "WASM: FORCE overriding CMAKE flags to -O1 to prevent wasm-opt")
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
    # WASM: Additional link options
    # Note: -O1 is set globally via CMAKE_CXX_FLAGS_RELEASE
    # This provides defense-in-depth even though we replaced wasm-opt
    target_link_options(${EXTENSION_NAME} PRIVATE "-O1")
    target_link_options(${LOADABLE_EXTENSION_NAME} PRIVATE "-O1")

    message(STATUS "WASM: Using -O1 link flags (global CMAKE flags also set)")
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
