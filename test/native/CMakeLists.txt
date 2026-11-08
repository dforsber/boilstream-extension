cmake_minimum_required(VERSION 3.15...3.30)
project(BoilstreamNativeProtocolDriver LANGUAGES CXX)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(DUCKDB_SOURCE_DIR
    ""
    CACHE PATH "Selected DuckDB source")
set(DUCKDB_BUILD_DIR
    ""
    CACHE PATH "Selected matching DuckDB build")
if(NOT EXISTS "${DUCKDB_SOURCE_DIR}/src/include/duckdb.hpp"
   OR NOT EXISTS
      "${DUCKDB_BUILD_DIR}/src/libduckdb${CMAKE_SHARED_LIBRARY_SUFFIX}")
  message(
    FATAL_ERROR "Select the actual DuckDB source and shared-library build")
endif()
add_executable(native_protocol_driver sql_driver.cpp)
target_include_directories(
  native_protocol_driver
  PRIVATE "${DUCKDB_SOURCE_DIR}/src/include"
          "${DUCKDB_SOURCE_DIR}/third_party/yyjson/include")
target_link_libraries(
  native_protocol_driver
  PRIVATE "${DUCKDB_BUILD_DIR}/src/libduckdb${CMAKE_SHARED_LIBRARY_SUFFIX}"
          "${DUCKDB_BUILD_DIR}/third_party/yyjson/libduckdb_yyjson.a")
