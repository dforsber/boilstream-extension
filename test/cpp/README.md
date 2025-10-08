# C++ Unit Tests for Boilstream Extension

## Note on Test Integration

The C++ unit tests in `test_boilstream_security.cpp` are currently **standalone** and need to be integrated into DuckDB's test framework.

## Integration Options

### Option 1: Copy to DuckDB Test Directory (Recommended)

For DuckDB extensions, C++ tests are typically part of the main DuckDB build:

```bash
# Copy test file to DuckDB test directory
cp test/cpp/test_boilstream_security.cpp duckdb/test/extension/

# Rebuild DuckDB with tests
cd duckdb
make unittest

# Run the specific test
./build/release/test/unittest --test-case="*boilstream*"
```

### Option 2: Standalone Test Build

Create a standalone test binary:

**File: `test/cpp/CMakeLists.txt`**

```cmake
cmake_minimum_required(VERSION 3.10)
project(boilstream_tests)

# Find DuckDB
find_package(duckdb REQUIRED)

# Add Catch2
find_package(Catch2 REQUIRED)

# Include directories
include_directories(../../src/include)
include_directories(../../duckdb/src/include)
include_directories(../../duckdb/third_party/catch)

# Test executable
add_executable(boilstream_test
    test_boilstream_security.cpp
    ../../src/boilstream_secret_storage.cpp
)

target_link_libraries(boilstream_test
    duckdb
    OpenSSL::SSL
    OpenSSL::Crypto
    Catch2::Catch2
)
```

Then build:
```bash
cd test/cpp
mkdir build
cd build
cmake ..
make
./boilstream_test
```

### Option 3: SQL Tests Only (Current Approach)

For now, focus on SQL tests which work out of the box:

```bash
# Run SQL tests
make test

# Tests are in:
# - test/sql/boilstream.test
# - test/sql/boilstream_security.test
```

## Test Coverage

The C++ tests provide comprehensive coverage of:
- PKCE code verifier generation (rejection sampling, entropy)
- Code challenge computation (SHA256, base64url)
- Token format validation
- Thread safety
- Security properties

However, these require proper integration with DuckDB's test framework to run.

## Recommended Approach

**For v0.2.0 release:**
1. Use SQL tests (already working): `make test`
2. Manual testing of PKCE functions with a test server
3. Add C++ tests to DuckDB's unittest in future version

**For future versions:**
1. Integrate C++ tests into DuckDB's test framework
2. Add mock HTTP server for integration testing
3. Add performance benchmarks
