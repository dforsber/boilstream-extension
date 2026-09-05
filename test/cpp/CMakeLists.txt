cmake_minimum_required(VERSION 3.15...3.30)
project(BoilstreamTests)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Detect Rust library location With Corrosion, libraries are built in:
# build/release/cargo/build/{target-triple}/release/ E.g.,
# build/release/cargo/build/aarch64-apple-darwin/release/libopaque_client.a
set(RUST_LIB_FOUND FALSE)
set(RUST_LIB_PATH "")

# Use DuckDB libraries from the extension build (not system DuckDB). Honour
# the workspace's direnv-managed external build when configured, while keeping
# the repository-local path as the standalone fallback.
if(DEFINED ENV{DUCKDB_BUILD_DIR} AND NOT "$ENV{DUCKDB_BUILD_DIR}" STREQUAL "")
  set(EXTENSION_BUILD_DIR "$ENV{DUCKDB_BUILD_DIR}")
else()
  set(EXTENSION_BUILD_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../build/release")
endif()
if(DEFINED ENV{DUCKDB_SOURCE_DIR} AND NOT "$ENV{DUCKDB_SOURCE_DIR}" STREQUAL "")
  set(DUCKDB_SOURCE_DIR "$ENV{DUCKDB_SOURCE_DIR}")
else()
  set(DUCKDB_SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../duckdb")
endif()

# The public extension uses the stock httpfs and Quack client extensions at
# runtime, but its standalone build does not necessarily build either external
# dependency. Require the integration lane to name the exact compatible
# artifacts it will load instead of inventing paths that may not exist.
set(BOILSTREAM_HTTPFS_EXTENSION_PATH
    ""
    CACHE FILEPATH "Path to a DuckDB-compatible httpfs.duckdb_extension")
set(BOILSTREAM_QUACK_EXTENSION_PATH
    ""
    CACHE FILEPATH "Path to a DuckDB-compatible quack.duckdb_extension")

function(resolve_required_extension_artifact variable_name artifact_name)
  set(candidate "${${variable_name}}")
  if(candidate STREQUAL "")
    set(candidate
        "${EXTENSION_BUILD_DIR}/extension/${artifact_name}/${artifact_name}.duckdb_extension"
    )
  endif()
  get_filename_component(candidate "${candidate}" REALPATH)
  if(NOT EXISTS "${candidate}")
    message(
      FATAL_ERROR
        "The C++ integration tests require ${artifact_name}. Set "
        "${variable_name} to the exact compatible "
        "${artifact_name}.duckdb_extension artifact.")
  else()
    set(${variable_name} "${candidate}" PARENT_SCOPE)
  endif()
endfunction()

resolve_required_extension_artifact(BOILSTREAM_HTTPFS_EXTENSION_PATH httpfs)
resolve_required_extension_artifact(BOILSTREAM_QUACK_EXTENSION_PATH quack)

get_filename_component(_httpfs_platform_dir
                       "${BOILSTREAM_HTTPFS_EXTENSION_PATH}" DIRECTORY)
get_filename_component(_quack_platform_dir
                       "${BOILSTREAM_QUACK_EXTENSION_PATH}" DIRECTORY)
if(NOT _httpfs_platform_dir STREQUAL _quack_platform_dir)
  message(
    FATAL_ERROR
      "httpfs and quack must come from the same DuckDB version/platform extension directory"
  )
endif()
get_filename_component(_stock_version_dir "${_quack_platform_dir}" DIRECTORY)
get_filename_component(BOILSTREAM_STOCK_EXTENSION_DIRECTORY
                       "${_stock_version_dir}" DIRECTORY)

# Priority 1: Look in Corrosion's cargo build directory (release builds)
file(GLOB_RECURSE RUST_LIB_CANDIDATES
     "${EXTENSION_BUILD_DIR}/cargo/build/*/release/libopaque_client.a")

if(RUST_LIB_CANDIDATES)
  list(GET RUST_LIB_CANDIDATES 0 RUST_LIB_PATH)
  set(RUST_LIB_FOUND TRUE)
  message(STATUS "Found Corrosion Rust library: ${RUST_LIB_PATH}")
else()
  # Priority 2: Check if copied to extension directory
  if(EXISTS "${EXTENSION_BUILD_DIR}/extension/boilstream/libopaque_client.a")
    set(RUST_LIB_PATH
        "${EXTENSION_BUILD_DIR}/extension/boilstream/libopaque_client.a")
    set(RUST_LIB_FOUND TRUE)
    message(STATUS "Found Rust library in extension dir: ${RUST_LIB_PATH}")
  else()
    # Priority 3: Fall back to manual cargo build locations (debug builds)
    file(
      GLOB_RECURSE
      RUST_LIB_CANDIDATES
      "${CMAKE_CURRENT_SOURCE_DIR}/../../opaque-client/target/*/debug/libopaque_client.a"
      "${CMAKE_CURRENT_SOURCE_DIR}/../../opaque-client/target/debug/libopaque_client.a"
    )
    if(RUST_LIB_CANDIDATES)
      list(GET RUST_LIB_CANDIDATES 0 RUST_LIB_PATH)
      set(RUST_LIB_FOUND TRUE)
      message(STATUS "Found Rust library (manual build): ${RUST_LIB_PATH}")
    endif()
  endif()
endif()

set(DUCKDB_LIBS
    "${EXTENSION_BUILD_DIR}/src/libduckdb_static.a"
    # v1.5 split ExtensionHelper::LoadAllExtensions out of libduckdb_static.a
    # into a separate loader library. Link the dummy loader so test executables
    # that do `DuckDB(":memory:")` resolve the symbol.
    "${EXTENSION_BUILD_DIR}/extension/libdummy_static_extension_loader.a"
    "${EXTENSION_BUILD_DIR}/extension/boilstream/libboilstream_extension.a"
    "${EXTENSION_BUILD_DIR}/extension/parquet/libparquet_extension.a"
    "${EXTENSION_BUILD_DIR}/extension/core_functions/libcore_functions_extension.a"
    "${EXTENSION_BUILD_DIR}/third_party/mbedtls/libduckdb_mbedtls.a"
    "${EXTENSION_BUILD_DIR}/third_party/fmt/libduckdb_fmt.a"
    "${EXTENSION_BUILD_DIR}/third_party/yyjson/libduckdb_yyjson.a"
    "${EXTENSION_BUILD_DIR}/third_party/re2/libduckdb_re2.a"
    "${EXTENSION_BUILD_DIR}/third_party/zstd/libduckdb_zstd.a"
    "${EXTENSION_BUILD_DIR}/third_party/miniz/libduckdb_miniz.a"
    "${EXTENSION_BUILD_DIR}/third_party/hyperloglog/libduckdb_hyperloglog.a"
    "${EXTENSION_BUILD_DIR}/third_party/fastpforlib/libduckdb_fastpforlib.a"
    "${EXTENSION_BUILD_DIR}/third_party/fsst/libduckdb_fsst.a"
    "${EXTENSION_BUILD_DIR}/third_party/utf8proc/libduckdb_utf8proc.a"
    "${EXTENSION_BUILD_DIR}/third_party/skiplist/libduckdb_skiplistlib.a"
    "${EXTENSION_BUILD_DIR}/third_party/libpg_query/libduckdb_pg_query.a")

# Check if extension is built
if(NOT EXISTS "${EXTENSION_BUILD_DIR}/src/libduckdb_static.a")
  message(
    FATAL_ERROR
      "DuckDB not built at ${EXTENSION_BUILD_DIR}. Please build the extension first with 'make'"
  )
endif()

# Download Catch2
include(FetchContent)
FetchContent_Declare(
  Catch2
  GIT_REPOSITORY https://github.com/catchorg/Catch2.git
  GIT_TAG v2.13.10)
FetchContent_MakeAvailable(Catch2)

# Add library search paths (must be before add_executable)
link_directories(/opt/homebrew/lib /usr/local/lib)

# Test executable
add_executable(
  boilstream_test
  test_boilstream_security.cpp ../../src/boilstream_secret_storage.cpp
  ../../src/opaque_wrapper.cpp)
# Note: mbedtls_wrapper.cpp is already in ${DUCKDB_LIB}, don't compile it again!

target_include_directories(
  boilstream_test
  PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../../src/include
          ${DUCKDB_SOURCE_DIR}/src/include
          ${DUCKDB_SOURCE_DIR}/third_party/mbedtls/include
          ${DUCKDB_SOURCE_DIR}/third_party/yyjson/include)

# Enable debug logging for OPAQUE authentication flows
target_compile_definitions(boilstream_test PRIVATE BOILSTREAM_DEBUG)

# Helper function to link Rust library and platform dependencies
function(link_rust_dependencies target_name)
  if(RUST_LIB_FOUND)
    target_link_libraries(${target_name} PRIVATE "${RUST_LIB_PATH}")

    # Platform-specific system libraries for Rust Match the same libraries used
    # in main CMakeLists.txt for Corrosion
    if(APPLE)
      target_link_libraries(
        ${target_name} PRIVATE "-framework Security" "-framework Foundation"
                               "-framework CoreFoundation" resolv)
    elseif(UNIX)
      target_link_libraries(${target_name} PRIVATE dl pthread)
    elseif(WIN32)
      # Include ALL Windows libraries needed by Rust (not just ws2_32, userenv,
      # bcrypt) These match what Corrosion links automatically
      if(MINGW)
        target_link_libraries(
          ${target_name}
          PRIVATE ws2_32
                  userenv
                  bcrypt
                  ntdll
                  stdc++
                  gcc
                  -static-libgcc
                  -static-libstdc++)
      else()
        # MSVC
        target_link_libraries(${target_name} PRIVATE ws2_32 userenv bcrypt
                                                     ntdll)
      endif()
    endif()
  else()
    message(
      WARNING "Rust library not found - ${target_name} may not link correctly")
  endif()
endfunction()

# Link extension's DuckDB and mbedTLS libraries
target_link_libraries(boilstream_test PRIVATE ${DUCKDB_LIBS} Catch2::Catch2)

# Link Rust dependencies
link_rust_dependencies(boilstream_test)

# Integration test executable
add_executable(boilstream_integration_test test_boilstream_integration.cpp)

target_include_directories(
  boilstream_integration_test
  PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../../src/include
          ${DUCKDB_SOURCE_DIR}/src/include)

# Enable debug logging for OPAQUE authentication flows
target_compile_definitions(boilstream_integration_test PRIVATE BOILSTREAM_DEBUG)

# Integration tests use system DuckDB and load the extension dynamically So we
# link against system DuckDB (not extension's build)
if(EXISTS "/opt/homebrew/lib/libduckdb.dylib")
  target_link_libraries(
    boilstream_integration_test PRIVATE /opt/homebrew/lib/libduckdb.dylib
                                        Catch2::Catch2)
elseif(EXISTS "/usr/local/lib/libduckdb.dylib")
  target_link_libraries(boilstream_integration_test
                        PRIVATE /usr/local/lib/libduckdb.dylib Catch2::Catch2)
else()
  target_link_libraries(boilstream_integration_test PRIVATE Catch2::Catch2)
  message(WARNING "System DuckDB not found - integration tests may not run")
endif()

# AWS Signing test executable (links with Rust library)
add_executable(aws_signing_test test_aws_signing.cpp)

target_include_directories(
  aws_signing_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../../src/include)

# Link with Rust OPAQUE client library
target_link_libraries(aws_signing_test PRIVATE Catch2::Catch2)
link_rust_dependencies(aws_signing_test)

# Registration FFI test executable (email/password validation, TOTP URI
# building)
add_executable(registration_ffi_test test_boilstream_registration.cpp)

target_include_directories(
  registration_ffi_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../../src/include)

# Link with Rust OPAQUE client library for registration FFI functions
target_link_libraries(registration_ffi_test PRIVATE Catch2::Catch2)
link_rust_dependencies(registration_ffi_test)

# Crypto test executable (integrity, HMAC, key derivation)
add_executable(
  boilstream_crypto_test
  test_boilstream_crypto.cpp ../../src/boilstream_secret_storage.cpp
  ../../src/opaque_wrapper.cpp)
# Note: mbedtls_wrapper.cpp is already in ${DUCKDB_LIB}, don't compile it again!

target_include_directories(
  boilstream_crypto_test
  PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../../src/include
          ${DUCKDB_SOURCE_DIR}/src/include
          ${DUCKDB_SOURCE_DIR}/third_party/mbedtls/include
          ${DUCKDB_SOURCE_DIR}/third_party/yyjson/include)

# Enable debug logging for OPAQUE authentication flows
target_compile_definitions(boilstream_crypto_test PRIVATE BOILSTREAM_DEBUG)

# Link extension's DuckDB and mbedTLS libraries
target_link_libraries(boilstream_crypto_test PRIVATE ${DUCKDB_LIBS}
                                                     Catch2::Catch2)

# Link Rust dependencies
link_rust_dependencies(boilstream_crypto_test)

# Conformance test executable (RFC 4231, RFC 5869, AWS SigV4 standards
# validation)
add_executable(
  boilstream_conformance_test
  test_boilstream_conformance.cpp ../../src/boilstream_secret_storage.cpp
  ../../src/opaque_wrapper.cpp)
# Note: mbedtls_wrapper.cpp is already in ${DUCKDB_LIB}, don't compile it again!

target_include_directories(
  boilstream_conformance_test
  PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../../src/include
          ${DUCKDB_SOURCE_DIR}/src/include
          ${DUCKDB_SOURCE_DIR}/third_party/mbedtls/include
          ${DUCKDB_SOURCE_DIR}/third_party/yyjson/include)

# Enable debug logging for OPAQUE authentication flows
target_compile_definitions(boilstream_conformance_test PRIVATE BOILSTREAM_DEBUG)

# Link extension's DuckDB and mbedTLS libraries
target_link_libraries(boilstream_conformance_test PRIVATE ${DUCKDB_LIBS}
                                                          Catch2::Catch2)

# Link Rust dependencies
link_rust_dependencies(boilstream_conformance_test)

# Encryption test executable (response encryption/decryption)
add_executable(
  boilstream_encryption_test
  test_boilstream_encryption.cpp ../../src/boilstream_secret_storage.cpp
  ../../src/opaque_wrapper.cpp)
# Note: mbedtls_wrapper.cpp is already in ${DUCKDB_LIB}, don't compile it again!

target_include_directories(
  boilstream_encryption_test
  PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../../src/include
          ${DUCKDB_SOURCE_DIR}/src/include
          ${DUCKDB_SOURCE_DIR}/third_party/mbedtls/include
          ${DUCKDB_SOURCE_DIR}/third_party/yyjson/include)

# Enable debug logging for OPAQUE authentication flows
target_compile_definitions(boilstream_encryption_test PRIVATE BOILSTREAM_DEBUG)

# Link extension's DuckDB and mbedTLS libraries
target_link_libraries(boilstream_encryption_test PRIVATE ${DUCKDB_LIBS}
                                                         Catch2::Catch2)

# Link Rust dependencies
link_rust_dependencies(boilstream_encryption_test)

# Catalog version test executable (rate limiting, version tracking)
add_executable(
  boilstream_catalog_version_test
  test_boilstream_catalog_versions.cpp ../../src/boilstream_secret_storage.cpp
  ../../src/opaque_wrapper.cpp)

target_include_directories(
  boilstream_catalog_version_test
  PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../../src/include
          ${DUCKDB_SOURCE_DIR}/src/include
          ${DUCKDB_SOURCE_DIR}/third_party/mbedtls/include
          ${DUCKDB_SOURCE_DIR}/third_party/yyjson/include)

# Enable debug logging for catalog version operations
target_compile_definitions(boilstream_catalog_version_test
                           PRIVATE BOILSTREAM_DEBUG)

# Link extension's DuckDB and mbedTLS libraries
target_link_libraries(boilstream_catalog_version_test PRIVATE ${DUCKDB_LIBS}
                                                              Catch2::Catch2)

# Link Rust dependencies
link_rust_dependencies(boilstream_catalog_version_test)

# Connection state test executable (per-connection authentication state
# isolation)
add_executable(boilstream_connection_state_test
               test_boilstream_connection_state.cpp)

target_include_directories(
  boilstream_connection_state_test
  PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../../src/include
          ${DUCKDB_SOURCE_DIR}/src/include)

# Enable debug logging
target_compile_definitions(boilstream_connection_state_test
                           PRIVATE BOILSTREAM_DEBUG)

# Link extension's DuckDB libraries (connection state is header-only, just needs
# DuckDB)
target_link_libraries(boilstream_connection_state_test PRIVATE ${DUCKDB_LIBS}
                                                               Catch2::Catch2)

# Link Rust dependencies (needed for DuckDB static lib)
link_rust_dependencies(boilstream_connection_state_test)

# WASM lock ordering test executable (verifies no deadlocks in lock patterns)
add_executable(wasm_lock_ordering_test test_wasm_lock_ordering.cpp)

target_include_directories(wasm_lock_ordering_test PRIVATE)

# This test only uses standard library threading, no DuckDB needed
target_link_libraries(wasm_lock_ordering_test PRIVATE Catch2::Catch2)

# Session routing test executable (per-connection session isolation)
add_executable(
  session_routing_test
  test_session_routing.cpp ../../src/boilstream_secret_storage.cpp
  ../../src/opaque_wrapper.cpp)

target_include_directories(
  session_routing_test
  PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../../src/include
          ${DUCKDB_SOURCE_DIR}/src/include
          ${DUCKDB_SOURCE_DIR}/third_party/mbedtls/include
          ${DUCKDB_SOURCE_DIR}/third_party/yyjson/include)

target_compile_definitions(session_routing_test PRIVATE BOILSTREAM_DEBUG)

target_link_libraries(session_routing_test PRIVATE ${DUCKDB_LIBS}
                                                   Catch2::Catch2)
link_rust_dependencies(session_routing_test)

# Input validation test executable (malicious/empty value handling)
add_executable(
  input_validation_test
  test_input_validation.cpp ../../src/boilstream_secret_storage.cpp
  ../../src/opaque_wrapper.cpp)

target_include_directories(
  input_validation_test
  PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../../src/include
          ${DUCKDB_SOURCE_DIR}/src/include
          ${DUCKDB_SOURCE_DIR}/third_party/mbedtls/include
          ${DUCKDB_SOURCE_DIR}/third_party/yyjson/include)

# Enable debug logging for input validation testing
target_compile_definitions(input_validation_test PRIVATE BOILSTREAM_DEBUG)

# Link extension's DuckDB and mbedTLS libraries
target_link_libraries(input_validation_test PRIVATE ${DUCKDB_LIBS}
                                                    Catch2::Catch2)

# Link Rust dependencies
link_rust_dependencies(input_validation_test)

# Quack ATTACH red test (TDD reproducer for the Phase 4 secret-lookup regression
# — bridge re-uses RestApiSecretStorage so we link it the same way as
# session_routing_test / input_validation_test).
add_executable(
  quack_attach_red_test
  test_quack_attach_red.cpp ../../src/boilstream_secret_storage.cpp
  ../../src/opaque_wrapper.cpp)

target_include_directories(
  quack_attach_red_test
  PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../../src/include
          ${DUCKDB_SOURCE_DIR}/src/include
          ${DUCKDB_SOURCE_DIR}/third_party/mbedtls/include
          ${DUCKDB_SOURCE_DIR}/third_party/yyjson/include)

target_compile_definitions(quack_attach_red_test PRIVATE BOILSTREAM_DEBUG)

target_link_libraries(quack_attach_red_test PRIVATE ${DUCKDB_LIBS}
                                                    Catch2::Catch2)
link_rust_dependencies(quack_attach_red_test)

# Quack planner bridge ABI tests compile the bridge source under review rather
# than silently reusing a possibly stale extension archive from DUCKDB_BUILD_DIR.
# The archive remains linked for the same full DuckDB dependency surface.
add_executable(quack_bridge_test test_quack_bridge.cpp ../../src/quack_bridge.cpp)

target_include_directories(
  quack_bridge_test
  PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../../src/include
          ${DUCKDB_SOURCE_DIR}/src/include)

target_link_libraries(quack_bridge_test PRIVATE ${DUCKDB_LIBS} Catch2::Catch2)
link_rust_dependencies(quack_bridge_test)

# Enable testing
enable_testing()
add_test(NAME BoilstreamSecurityTests COMMAND boilstream_test)
add_test(NAME BoilstreamCryptoTests COMMAND boilstream_crypto_test)
add_test(NAME BoilstreamConformanceTests COMMAND boilstream_conformance_test)
add_test(NAME BoilstreamEncryptionTests COMMAND boilstream_encryption_test)
add_test(NAME BoilstreamCatalogVersionTests
         COMMAND boilstream_catalog_version_test)
add_test(NAME BoilstreamConnectionStateTests
         COMMAND boilstream_connection_state_test)
add_test(NAME WasmLockOrderingTests COMMAND wasm_lock_ordering_test)
add_test(NAME InputValidationTests COMMAND input_validation_test)
# The CTest lane is deliberately non-interactive: it proves that the exact
# loadable artifact works in stock DuckDB. Server/OPAQUE cases require
# single-use credentials and belong to the product and staging gates.
add_test(NAME BoilstreamIntegrationTests COMMAND boilstream_integration_test
                                                 "[local]")
set_tests_properties(
  BoilstreamIntegrationTests
  PROPERTIES
    ENVIRONMENT
    "BOILSTREAM_EXTENSION_PATH=${EXTENSION_BUILD_DIR}/extension/boilstream/boilstream.duckdb_extension;BOILSTREAM_HTTPFS_EXTENSION_PATH=${BOILSTREAM_HTTPFS_EXTENSION_PATH};BOILSTREAM_STOCK_EXTENSION_DIRECTORY=${BOILSTREAM_STOCK_EXTENSION_DIRECTORY}"
)
add_test(NAME AwsSigningTests COMMAND aws_signing_test)
add_test(NAME RegistrationFFITests COMMAND registration_ffi_test)
add_test(NAME SessionRoutingTests COMMAND session_routing_test)
add_test(NAME QuackAttachRedTests COMMAND quack_attach_red_test)
add_test(NAME QuackBridgeTests COMMAND quack_bridge_test)
