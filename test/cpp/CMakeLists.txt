cmake_minimum_required(VERSION 3.14)
project(BoilstreamTests)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Note: DuckDB library must be available in the system or built first You can
# set DUCKDB_LIB manually if needed
if(NOT DEFINED DUCKDB_LIB)
  # Try common locations
  if(EXISTS "/usr/local/lib/libduckdb.dylib")
    set(DUCKDB_LIB "/usr/local/lib/libduckdb.dylib")
  elseif(EXISTS "/opt/homebrew/lib/libduckdb.dylib")
    set(DUCKDB_LIB "/opt/homebrew/lib/libduckdb.dylib")
  else()
    message(STATUS "DuckDB library not found, tests will compile but not link")
    set(DUCKDB_LIB "")
  endif()
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
  ../../duckdb/third_party/mbedtls/mbedtls_wrapper.cpp)

target_include_directories(
  boilstream_test
  PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../../src/include
          ${CMAKE_CURRENT_SOURCE_DIR}/../../duckdb/src/include
          ${CMAKE_CURRENT_SOURCE_DIR}/../../duckdb/third_party/mbedtls/include
          ${CMAKE_CURRENT_SOURCE_DIR}/../../duckdb/third_party/yyjson/include)

if(DUCKDB_LIB)
  target_link_libraries(boilstream_test PRIVATE ${DUCKDB_LIB} Catch2::Catch2
                                                mbedcrypto mbedx509 mbedtls)
else()
  target_link_libraries(boilstream_test PRIVATE Catch2::Catch2 mbedcrypto
                                                mbedx509 mbedtls)
  message(WARNING "Building without DuckDB library - executable may not run")
endif()

# Integration test executable
add_executable(
  boilstream_integration_test test_boilstream_integration.cpp)

target_include_directories(
  boilstream_integration_test
  PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../../src/include
          ${CMAKE_CURRENT_SOURCE_DIR}/../../duckdb/src/include)

if(DUCKDB_LIB)
  target_link_libraries(boilstream_integration_test PRIVATE ${DUCKDB_LIB}
                                                             Catch2::Catch2)
else()
  target_link_libraries(boilstream_integration_test PRIVATE Catch2::Catch2)
  message(
    WARNING "Building integration tests without DuckDB library - may not run")
endif()

# Enable testing
enable_testing()
add_test(NAME BoilstreamSecurityTests COMMAND boilstream_test)
add_test(NAME BoilstreamIntegrationTests COMMAND boilstream_integration_test)
