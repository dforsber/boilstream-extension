cmake_minimum_required(VERSION 3.15...3.30)

# Set extension name here
set(TARGET_NAME boilstream)

# DuckDB provides mbedTLS for all platforms (including WASM)
# We use duckdb_mbedtls::MbedTlsWrapper for cryptographic operations
# OpenSSL is NOT needed - removed to support WASM builds

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

    # Workaround for wasm-opt incompatibility with newer Emscripten versions
    # Replace wasm-opt in EMSDK with a wrapper that filters out --enable-bulk-memory-opt
    if(DEFINED ENV{EMSDK})
        set(EMSDK_WASM_OPT "$ENV{EMSDK}/upstream/bin/wasm-opt")
        set(EMSDK_WASM_OPT_REAL "$ENV{EMSDK}/upstream/bin/wasm-opt.real")

        # Only create wrapper if we haven't already
        if(EXISTS "${EMSDK_WASM_OPT}" AND NOT EXISTS "${EMSDK_WASM_OPT_REAL}")
            message(STATUS "WASM: Creating wasm-opt wrapper to fix --enable-bulk-memory-opt incompatibility")

            # Backup original wasm-opt
            execute_process(
                COMMAND ${CMAKE_COMMAND} -E rename "${EMSDK_WASM_OPT}" "${EMSDK_WASM_OPT_REAL}"
                RESULT_VARIABLE RENAME_RESULT
            )

            if(RENAME_RESULT EQUAL 0)
                # Read template and replace placeholder with real path
                file(READ "${CMAKE_CURRENT_SOURCE_DIR}/scripts/wasm-opt-wrapper-template.sh" WRAPPER_CONTENT)
                string(REPLACE "WASM_OPT_REAL_PATH" "${EMSDK_WASM_OPT_REAL}" WRAPPER_CONTENT "${WRAPPER_CONTENT}")

                # Write wrapper script
                file(WRITE "${EMSDK_WASM_OPT}" "${WRAPPER_CONTENT}")

                # Make executable
                execute_process(COMMAND chmod +x "${EMSDK_WASM_OPT}")

                message(STATUS "WASM: Wrapper created, original wasm-opt backed up to wasm-opt.real")
            else()
                message(WARNING "WASM: Failed to rename wasm-opt, build may fail")
            endif()
        elseif(EXISTS "${EMSDK_WASM_OPT_REAL}")
            message(STATUS "WASM: wasm-opt wrapper already exists (using existing)")
        endif()
    else()
        message(WARNING "WASM: EMSDK environment variable not set, cannot install wasm-opt wrapper")
    endif()

    # Add WASM-specific compile definitions required by DuckDB extensions
    add_compile_definitions(WASM_LOADABLE_EXTENSIONS=1)

    # Add exception handling flags for wasm_eh builds
    if(DEFINED ENV{WASM_BUILD_TYPE})
        if($ENV{WASM_BUILD_TYPE} STREQUAL "wasm_eh")
            add_compile_options(-fwasm-exceptions)
            add_compile_definitions(WEBDB_FAST_EXCEPTIONS=1)
            message(STATUS "WASM: Using exception handling mode (wasm_eh)")
        elseif($ENV{WASM_BUILD_TYPE} STREQUAL "wasm_threads")
            add_compile_options(-pthread)
            add_compile_definitions(WITH_WASM_THREADS=1 WITH_WASM_SIMD=1 WITH_WASM_BULK_MEMORY=1)
            message(STATUS "WASM: Using threads mode (wasm_threads)")
        endif()
    endif()

    message(STATUS "WASM: Configured with DuckDB extension flags")
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

# Enable debug logging conditionally (set -DBOILSTREAM_DEBUG=ON to enable)
# For WASM, always enable for easier browser debugging
if(IS_WASM_BUILD OR BOILSTREAM_DEBUG)
    target_compile_definitions(${EXTENSION_NAME} PRIVATE BOILSTREAM_DEBUG)
    target_compile_definitions(${LOADABLE_EXTENSION_NAME} PRIVATE BOILSTREAM_DEBUG)
    if(IS_WASM_BUILD)
        message(STATUS "WASM: Debug logging enabled (browser console)")
    else()
        message(STATUS "Native: Debug logging enabled (stderr)")
    endif()
endif()

# Link Rust OPAQUE client library (includes all crypto operations)
# opaque_client_rust is either:
# - WASM: imported target from manual cargo build
# - Native: alias to Corrosion's opaque_client-static target
# All cryptographic operations (SHA256, HMAC, HKDF, AES-GCM) are now handled by Rust
target_link_libraries(${EXTENSION_NAME} opaque_client_rust)
target_link_libraries(${LOADABLE_EXTENSION_NAME} opaque_client_rust)

# Platform-specific configuration
if(IS_WASM_BUILD)
    # WASM: Link options based on build type
    if(DEFINED ENV{WASM_BUILD_TYPE})
        if($ENV{WASM_BUILD_TYPE} STREQUAL "wasm_eh")
            target_link_options(${EXTENSION_NAME} PRIVATE "-fwasm-exceptions")
            target_link_options(${LOADABLE_EXTENSION_NAME} PRIVATE "-fwasm-exceptions")
        elseif($ENV{WASM_BUILD_TYPE} STREQUAL "wasm_threads")
            target_link_options(${EXTENSION_NAME} PRIVATE "-pthread")
            target_link_options(${LOADABLE_EXTENSION_NAME} PRIVATE "-pthread")
        endif()
    endif()

    # Add POST_BUILD to re-export with both entry points
    # DuckDB's POST_BUILD only exports _duckdb_cpp_init, but WASM needs _init
    # Note: In WASM builds, $<TARGET_FILE> already includes .wasm extension
    # emcc will overwrite the input file when input and output are the same
    add_custom_command(TARGET ${LOADABLE_EXTENSION_NAME} POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E echo "Re-exporting WASM module with boilstream_init..."
        COMMAND emcc
            $<TARGET_FILE:${LOADABLE_EXTENSION_NAME}>
            -o $<TARGET_FILE:${LOADABLE_EXTENSION_NAME}>
            -O0 -sSIDE_MODULE=2
            -sEXPORTED_FUNCTIONS=_boilstream_init,_boilstream_duckdb_cpp_init,___wasm_call_ctors
            -fwasm-exceptions
        COMMENT "Adding boilstream_init export for DuckDB WASM compatibility (no optimization to preserve Rust symbols)"
    )

    # Add POST_BUILD to append metadata
    # This is required for DuckDB to recognize the extension ABI version
    # Note: In WASM builds, $<TARGET_FILE> already includes .wasm extension
    # So we append to the .wasm file directly, not .wasm.wasm
    add_custom_command(TARGET ${LOADABLE_EXTENSION_NAME} POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E echo "Appending extension metadata..."
        COMMAND ${CMAKE_COMMAND} -E echo "Extension file: $<TARGET_FILE:${LOADABLE_EXTENSION_NAME}>"
        COMMAND ${CMAKE_COMMAND}
            -DMETA1=4
            -DABI_TYPE=CPP
            -DEXTENSION=$<TARGET_FILE:${LOADABLE_EXTENSION_NAME}>
            -DPLATFORM_FILE=${CMAKE_BINARY_DIR}/duckdb_platform_out
            -DVERSION_FIELD=v1.4.1
            -DEXTENSION_VERSION=unknown
            -DNULL_FILE=${CMAKE_CURRENT_SOURCE_DIR}/duckdb/scripts/null.txt
            -P ${CMAKE_CURRENT_SOURCE_DIR}/duckdb/scripts/append_metadata.cmake
        COMMENT "Appending extension metadata for DuckDB compatibility"
    )

    message(STATUS "WASM: Added POST_BUILD to export both entry points and append metadata")
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
