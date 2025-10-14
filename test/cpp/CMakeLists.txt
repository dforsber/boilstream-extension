cmake_minimum_required(VERSION 3.15...3.30)
project(BoilstreamTests)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Detect Rust library location With Corrosion, libraries are built in:
# build/release/cargo/build/{target-triple}/release/ E.g.,
# build/release/cargo/build/aarch64-apple-darwin/release/libopaque_client.a
set(RUST_LIB_FOUND FALSE)
set(RUST_LIB_PATH "")

# Use DuckDB libraries from the extension build (not system DuckDB)
set(EXTENSION_BUILD_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../build/release")

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
          ${CMAKE_CURRENT_SOURCE_DIR}/../../duckdb/src/include
          ${CMAKE_CURRENT_SOURCE_DIR}/../../duckdb/third_party/mbedtls/include
          ${CMAKE_CURRENT_SOURCE_DIR}/../../duckdb/third_party/yyjson/include)

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
          ${CMAKE_CURRENT_SOURCE_DIR}/../../duckdb/src/include)

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

# Crypto test executable (integrity, HMAC, key derivation)
add_executable(
  boilstream_crypto_test
  test_boilstream_crypto.cpp ../../src/boilstream_secret_storage.cpp
  ../../src/opaque_wrapper.cpp)
# Note: mbedtls_wrapper.cpp is already in ${DUCKDB_LIB}, don't compile it again!

target_include_directories(
  boilstream_crypto_test
  PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../../src/include
          ${CMAKE_CURRENT_SOURCE_DIR}/../../duckdb/src/include
          ${CMAKE_CURRENT_SOURCE_DIR}/../../duckdb/third_party/mbedtls/include
          ${CMAKE_CURRENT_SOURCE_DIR}/../../duckdb/third_party/yyjson/include)

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
          ${CMAKE_CURRENT_SOURCE_DIR}/../../duckdb/src/include
          ${CMAKE_CURRENT_SOURCE_DIR}/../../duckdb/third_party/mbedtls/include
          ${CMAKE_CURRENT_SOURCE_DIR}/../../duckdb/third_party/yyjson/include)

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
          ${CMAKE_CURRENT_SOURCE_DIR}/../../duckdb/src/include
          ${CMAKE_CURRENT_SOURCE_DIR}/../../duckdb/third_party/mbedtls/include
          ${CMAKE_CURRENT_SOURCE_DIR}/../../duckdb/third_party/yyjson/include)

# Enable debug logging for OPAQUE authentication flows
target_compile_definitions(boilstream_encryption_test PRIVATE BOILSTREAM_DEBUG)

# Link extension's DuckDB and mbedTLS libraries
target_link_libraries(boilstream_encryption_test PRIVATE ${DUCKDB_LIBS}
                                                         Catch2::Catch2)

# Link Rust dependencies
link_rust_dependencies(boilstream_encryption_test)

# Enable testing
enable_testing()
add_test(NAME BoilstreamSecurityTests COMMAND boilstream_test)
add_test(NAME BoilstreamCryptoTests COMMAND boilstream_crypto_test)
add_test(NAME BoilstreamConformanceTests COMMAND boilstream_conformance_test)
add_test(NAME BoilstreamEncryptionTests COMMAND boilstream_encryption_test)
add_test(NAME BoilstreamIntegrationTests COMMAND boilstream_integration_test)
add_test(NAME AwsSigningTests COMMAND aws_signing_test)
