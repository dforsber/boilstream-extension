# Boilstream Extension Test Suite

This directory contains comprehensive tests for the Boilstream DuckDB extension, with a focus on security features and PKCE token exchange.

## Test Structure

### C++ Unit Tests (`test/cpp/`)

**File:** `test_boilstream_security.cpp`

C++ unit tests using the Catch2 framework. These tests focus on low-level functionality and security properties:

#### PKCE Code Verifier Generation
- ✅ Correct length (64 characters)
- ✅ Valid base64url characters only
- ✅ Uniqueness (no collisions in 1000 samples)
- ✅ High entropy (chi-square distribution test)
- ✅ Rejection sampling (unbiased random distribution)

#### PKCE Code Challenge Computation
- ✅ Correct output format (43-char base64url)
- ✅ Deterministic (same input → same output)
- ✅ One-way function (cannot recover verifier)
- ✅ RFC 7636 test vector validation

#### Token Format Validation
- ✅ Valid tokens (32-512 chars, alphanumeric + - and _)
- ✅ Rejects empty tokens
- ✅ Rejects tokens that are too short (< 32)
- ✅ Rejects tokens that are too long (> 512)
- ✅ Rejects invalid characters
- ✅ Descriptive error messages

#### Session State Management
- ✅ Token validity checks
- ✅ Rotation timing logic
- ✅ Session clearing

#### Thread Safety
- ✅ Concurrent code verifier generation
- ✅ Concurrent session clearing
- ✅ No race conditions

#### Security Properties
- ✅ Unpredictable verifiers (high Hamming distance)
- ✅ One-way challenge computation
- ✅ No pattern in generated values

### SQL Integration Tests (`test/sql/`)

**File:** `boilstream.test` - Basic extension functionality
**File:** `boilstream_security.test` - Security-focused validation tests

SQL tests using DuckDB's SQLLogicTest framework:

#### URL Validation
- ✅ HTTPS required for non-localhost
- ✅ HTTP allowed for localhost, 127.0.0.1, ::1
- ✅ Bypass prevention (subdomain.localhost, path tricks, query params)
- ✅ Proper hostname extraction

#### Input Validation
- ✅ Bootstrap token required
- ✅ URL format validation
- ✅ Token delimiter validation

#### Error Handling
- ✅ Descriptive error messages
- ✅ Proper exception types

## Running Tests

### Run All Tests
```bash
make test
```

### Run Tests in Debug Mode
```bash
make test_debug
```

### Run Only C++ Unit Tests
```bash
# Build the test binary
make

# Run with Catch2 options
./build/release/test/unittest --test-case="*boilstream*"
```

### Run Specific Test Cases
```bash
# Run only PKCE tests
./build/release/test/unittest --test-case="*PKCE*"

# Run only security tests
./build/release/test/unittest --tag="[security]"

# Run with verbose output
./build/release/test/unittest --test-case="*boilstream*" --success
```

### Run Only SQL Tests
```bash
python3 scripts/run_tests_one_by_one.py test/sql/boilstream*.test
```

## Test Coverage

### Security Fixes Tested

All critical and high-priority security fixes from v0.2.0 are covered:

| Fix | C++ Test | SQL Test |
|-----|----------|----------|
| CRITICAL-1: PKCE rotation protocol | ✅ (challenge computation) | N/A |
| CRITICAL-2: Weak RNG | ✅ (entropy, distribution) | N/A |
| CRITICAL-3: Race conditions | ✅ (thread safety) | N/A |
| HIGH-4: Bootstrap token leakage | ✅ (implicit) | ✅ (validation) |
| HIGH-5: Inconsistent state | N/A (integration) | ✅ (error paths) |
| HIGH-6: Exchange race condition | ✅ (thread safety) | N/A |
| HIGH-7: Token validation | ✅ (format checks) | ✅ (error messages) |
| HIGH-8: Rotation failures | N/A (integration) | N/A |
| HIGH-9: URL bypass | N/A | ✅ (comprehensive) |

### What's NOT Tested (Requires Mock Server)

These require a running test server with PKCE endpoints:

- **Token Exchange Flow**: Actual HTTP exchange of bootstrap → session token
- **Token Rotation Flow**: Actual rotation with new code_challenge
- **Server Response Validation**: Parsing real server responses
- **Network Error Handling**: Timeout, connection failures, retries
- **Multi-threaded Token Rotation**: Concurrent rotation under load

**Recommendation**: Implement integration tests with a mock HTTP server or test against a real development server.

## Test Maintenance

### Adding New Tests

**C++ Unit Test:**
1. Add test case to `test/cpp/test_boilstream_security.cpp`
2. Use Catch2 `TEST_CASE` macro with appropriate tags
3. Rebuild: `make`

**SQL Test:**
1. Add test to `test/sql/boilstream_security.test` or create new `.test` file
2. Follow SQLLogicTest format (see existing tests)
3. Run: `make test`

### Debugging Failed Tests

**C++ Tests:**
```bash
# Run with GDB
gdb ./build/debug/test/unittest
(gdb) run --test-case="*PKCE*"

# Run with verbose output
./build/release/test/unittest --test-case="*boilstream*" --success --break
```

**SQL Tests:**
```bash
# Run single test file with verbose output
python3 scripts/run_tests_one_by_one.py test/sql/boilstream_security.test --verbose
```

## Continuous Integration

These tests should be run as part of CI/CD:

```yaml
# Example GitHub Actions workflow
- name: Build Extension
  run: make release

- name: Run Unit Tests
  run: make test

- name: Run C++ Tests
  run: ./build/release/test/unittest --test-case="*boilstream*"

- name: Run SQL Tests
  run: make test_debug
```

## Performance Benchmarks

Some tests include performance assertions:

- **Code Verifier Generation**: Should generate 1000 unique values in < 1 second
- **Challenge Computation**: Should compute 1000 challenges in < 1 second
- **Concurrent Access**: 10 threads × 100 operations should complete in < 5 seconds

If these fail, there may be a performance regression.

## Security Test Philosophy

These tests verify **defensive security properties**:

1. **Randomness Quality**: PKCE verifiers are cryptographically random
2. **Input Validation**: All inputs are validated before use
3. **Error Handling**: Errors don't leak sensitive information
4. **Thread Safety**: No race conditions under concurrent access
5. **Protocol Correctness**: PKCE implementation follows RFC 7636

**What We Don't Test (Out of Scope):**
- Offensive security (penetration testing)
- Server-side vulnerabilities
- Network-level attacks (MITM, etc.)
- Social engineering

## Future Test Additions

Recommended additions for comprehensive coverage:

1. **Mock HTTP Server**: Test full exchange and rotation flows
2. **Fuzzing**: Random input fuzzing for crash detection
3. **Load Testing**: High-concurrency scenarios (1000+ threads)
4. **Memory Safety**: Valgrind/AddressSanitizer tests
5. **Timing Attacks**: Constant-time operation verification
6. **Integration Tests**: Test with real DuckDB secrets storage

## Contact

For questions about tests or to report test failures:
- File an issue: https://github.com/yourusername/boilstream-extension/issues
- Include test output and DuckDB version
