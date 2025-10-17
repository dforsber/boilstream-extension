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

    # Replace wasm-opt with wrapper to filter deprecated --enable-bulk-memory-opt flag
    # This works with Emscripten 3.1.71+ which removed this flag
    # emcc uses absolute paths to wasm-opt, so we must replace the binary itself

    # Find wasm-opt in PATH (should be from emsdk)
    execute_process(
        COMMAND which wasm-opt
        OUTPUT_VARIABLE WASM_OPT_PATH
        OUTPUT_STRIP_TRAILING_WHITESPACE
        ERROR_QUIET
    )

    if(WASM_OPT_PATH)
        message(STATUS "WASM: Found wasm-opt at ${WASM_OPT_PATH}")

        # Backup the original wasm-opt
        execute_process(
            COMMAND ${CMAKE_COMMAND} -E copy "${WASM_OPT_PATH}" "${WASM_OPT_PATH}.original"
            RESULT_VARIABLE BACKUP_RESULT
            ERROR_QUIET
        )

        if(BACKUP_RESULT EQUAL 0)
            message(STATUS "WASM: Backed up original wasm-opt to ${WASM_OPT_PATH}.original")

            # Create wrapper script that calls the original wasm-opt
            file(WRITE "${WASM_OPT_PATH}.tmp"
                "#!/bin/bash\n"
                "# Wrapper to filter deprecated --enable-bulk-memory-opt flag\n"
                "FILTERED_ARGS=()\n"
                "for arg in \"$@\"; do\n"
                "    if [ \"$arg\" != \"--enable-bulk-memory-opt\" ]; then\n"
                "        FILTERED_ARGS+=(\"$arg\")\n"
                "    fi\n"
                "done\n"
                "exec \"${WASM_OPT_PATH}.original\" \"${FILTERED_ARGS[@]}\"\n"
            )

            # Replace wasm-opt with our wrapper
            execute_process(COMMAND chmod +x "${WASM_OPT_PATH}.tmp")
            execute_process(
                COMMAND ${CMAKE_COMMAND} -E copy "${WASM_OPT_PATH}.tmp" "${WASM_OPT_PATH}"
                RESULT_VARIABLE REPLACE_RESULT
            )
            execute_process(COMMAND ${CMAKE_COMMAND} -E remove "${WASM_OPT_PATH}.tmp")

            if(REPLACE_RESULT EQUAL 0)
                message(STATUS "WASM: Replaced wasm-opt with wrapper to filter deprecated flags")
            else()
                message(WARNING "WASM: Failed to replace wasm-opt with wrapper")
            endif()
        else()
            message(WARNING "WASM: Failed to backup wasm-opt, skipping wrapper installation")
        endif()
    else()
        message(WARNING "WASM: Could not find wasm-opt in PATH")
    endif()

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
    # Note: -O1 is set globally via CMAKE_CXX_FLAGS_RELEASE (line 24-25)
    # This prevents DuckDB's -O3 from triggering wasm-opt with deprecated flags
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
