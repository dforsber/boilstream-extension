/**
 * Executable WASM FFI regression tests using the production C ABI.
 * Run test-ffi.sh with the SDK pinned in test/wasm/baseline.json.
 * BOILSTREAM_RUST_WASM_LIB selects the exact archive from an extension build.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "opaque_client.h"
#ifdef __EMSCRIPTEN_PTHREADS__
#include <emscripten/threading.h>
#endif

// Test result tracking
static int tests_passed = 0;
static int tests_failed = 0;

#define TEST(name) printf("\n🧪 Testing: %s\n", name)
#define ASSERT(condition, message) \
    do { \
        if (condition) { \
            printf("  ✅ PASS: %s\n", message); \
            tests_passed++; \
        } else { \
            printf("  ❌ FAIL: %s\n", message); \
            tests_failed++; \
        } \
    } while(0)

/**
 * Test 1: Registration Start
 * Verifies that we can start a registration with a password
 */
void test_registration_start() {
    TEST("Registration Start");

    const char *password = "test_password_123";
    RegistrationState *state = NULL;

    OpaqueResult result = opaque_client_registration_start(password, strlen(password), &state);

    ASSERT(result.error == OPAQUE_SUCCESS, "Registration start returns success");
    ASSERT(state != NULL, "Registration state is created");
    ASSERT(result.buffer.data != NULL, "Registration request is generated");
    ASSERT(result.buffer.len == 32, "Ristretto255 registration request is 32 bytes");

    printf("  ℹ️  Registration request size: %zu bytes\n", result.buffer.len);

    // Cleanup
    if (result.buffer.data != NULL) {
        opaque_free_buffer(result.buffer);
    }
    if (state != NULL) {
        opaque_free_registration_state(state);
    }
}

/**
 * Test 2: Login Start
 * Verifies that we can start a login with a password
 */
void test_login_start() {
    TEST("Login Start");

    const char *password = "test_password_123";
    LoginState *state = NULL;

    OpaqueResult result = opaque_client_login_start(password, strlen(password), &state);

    ASSERT(result.error == OPAQUE_SUCCESS, "Login start returns success");
    ASSERT(state != NULL, "Login state is created");
    ASSERT(result.buffer.data != NULL, "Credential request is generated");
    ASSERT(result.buffer.len == 96, "Ristretto255 credential request is 96 bytes");

    printf("  ℹ️  Credential request size: %zu bytes\n", result.buffer.len);

    // Cleanup
    if (result.buffer.data != NULL) {
        opaque_free_buffer(result.buffer);
    }
    if (state != NULL) {
        opaque_free_login_state(state);
    }
}

/**
 * Test 3: Null Pointer Handling
 * Verifies that null pointers are handled gracefully
 */
void test_null_pointer_handling() {
    TEST("Null Pointer Handling");

    // Try registration with null password
    OpaqueResult result1 = opaque_client_registration_start(NULL, 0, NULL);
    ASSERT(result1.error == OPAQUE_INVALID_INPUT, "Null password rejected in registration");

    // Try login with null password
    OpaqueResult result2 = opaque_client_login_start(NULL, 0, NULL);
    ASSERT(result2.error == OPAQUE_INVALID_INPUT, "Null password rejected in login");
}

/**
 * Test 4: Empty Password Handling
 * Verifies that empty passwords are handled correctly
 */
void test_empty_password() {
    TEST("Empty Password Handling");

    const char *empty_password = "";
    RegistrationState *state = NULL;

    OpaqueResult result = opaque_client_registration_start(empty_password, 0, &state);

    // Empty passwords should be accepted (application can enforce minimum length)
    ASSERT(result.error == OPAQUE_SUCCESS,
           "Protocol permits empty password; application enforces strength");

    // Cleanup if successful
    if (result.error == OPAQUE_SUCCESS) {
        if (result.buffer.data != NULL) {
            opaque_free_buffer(result.buffer);
        }
        if (state != NULL) {
            opaque_free_registration_state(state);
        }
    }
}

/**
 * Test 5: Multiple Registrations
 * Verifies that we can perform multiple registrations
 */
void test_multiple_registrations() {
    TEST("Multiple Sequential Registrations");

    const char *password1 = "password_1";
    const char *password2 = "password_2";
    const char *password3 = "password_3";

    for (int i = 0; i < 3; i++) {
        const char *password = (i == 0) ? password1 : (i == 1) ? password2 : password3;
        RegistrationState *state = NULL;

        OpaqueResult result = opaque_client_registration_start(password, strlen(password), &state);

        ASSERT(result.error == OPAQUE_SUCCESS, "Sequential registration succeeds");

        // Cleanup
        if (result.buffer.data != NULL) {
            opaque_free_buffer(result.buffer);
        }
        if (state != NULL) {
            opaque_free_registration_state(state);
        }
    }
}

/**
 * Test 6: Deterministic vs Non-deterministic
 * Verifies that registrations with same password produce different outputs (randomized)
 */
void test_determinism() {
    TEST("Registration Randomization");

    const char *password = "same_password";
    RegistrationState *state1 = NULL;
    RegistrationState *state2 = NULL;

    OpaqueResult result1 = opaque_client_registration_start(password, strlen(password), &state1);
    OpaqueResult result2 = opaque_client_registration_start(password, strlen(password), &state2);

    ASSERT(result1.error == OPAQUE_SUCCESS && result2.error == OPAQUE_SUCCESS,
           "Both registrations succeed");

    // Requests should be different (randomized nonces/keys)
    int are_different = 0;
    if (result1.buffer.data && result2.buffer.data && result1.buffer.len == result2.buffer.len) {
        are_different = memcmp(result1.buffer.data, result2.buffer.data, result1.buffer.len) != 0;
    }

    ASSERT(are_different, "Registration requests are randomized (different for same password)");

    // Cleanup
    if (result1.buffer.data != NULL) {
        opaque_free_buffer(result1.buffer);
    }
    if (result2.buffer.data != NULL) {
        opaque_free_buffer(result2.buffer);
    }
    if (state1 != NULL) {
        opaque_free_registration_state(state1);
    }
    if (state2 != NULL) {
        opaque_free_registration_state(state2);
    }
}

// RFC 4231 test case 1: independent, published HMAC-SHA256 known-answer vector.
void test_signing_vector(void) {
    TEST("RFC 4231 HMAC-SHA256 and canonical payload digest");
    const uint8_t key[20] = { [0 ... 19] = 0x0b };
    const char expected[] = "sDRMYdjbOFNcqK/OrwvxK4gdwgDJgz2nJuk3bC4yz/c=";
    OpaqueResult result = aws_sign_canonical_request(key, sizeof(key), "Hi There", 8);
    ASSERT(result.error == OPAQUE_SUCCESS && result.buffer.len == strlen(expected) &&
           memcmp(result.buffer.data, expected, strlen(expected)) == 0, "HMAC matches RFC 4231 case 1");
    opaque_free_buffer(result.buffer);
    result = aws_sign_canonical_request(NULL, 0, "Hi There", 8);
    ASSERT(result.error == OPAQUE_INVALID_INPUT, "Null signing key is rejected");
    const char canonical[] = "GET\n/\n\nhost:example.com\n\nhost\ne3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    result = aws_build_canonical_request("GET", 3, "/", 1, "", 0, "host:example.com\n", 17, "host", 4, NULL, 0);
    ASSERT(result.error == OPAQUE_SUCCESS && result.buffer.len == strlen(canonical) &&
           memcmp(result.buffer.data, canonical, strlen(canonical)) == 0, "Canonical request includes known SHA256 empty digest");
    opaque_free_buffer(result.buffer);
    result = aws_build_canonical_request("GET", 3, "/", 1, "", 0, "host:example.com\n", 17, "host", 4, NULL, 1);
    ASSERT(result.error == OPAQUE_INVALID_INPUT, "Null payload with nonzero length is rejected");
}

void test_malformed_responses(void) {
    TEST("Malformed OPAQUE server messages fail without publishing keys");
    RegistrationState *registration = NULL;
    LoginState *login = NULL;
    OpaqueBuffer upload = {0}, export_key = {0}, session_key = {0};
    const uint8_t invalid[] = {0xff};
    OpaqueResult r = opaque_client_registration_start("password", 8, &registration);
    ASSERT(r.error == OPAQUE_SUCCESS, "Registration state allocated");
    opaque_free_buffer(r.buffer);
    if (registration) {
        ASSERT(opaque_client_registration_finish(registration, invalid, 1, &upload, &export_key) ==
               OPAQUE_SERIALIZATION_ERROR, "Malformed registration response rejected");
        ASSERT(!upload.data && !export_key.data, "Registration failure publishes no outputs");
    }
    r = opaque_client_login_start("password", 8, &login);
    ASSERT(r.error == OPAQUE_SUCCESS, "Login state allocated");
    opaque_free_buffer(r.buffer);
    if (login) {
        ASSERT(opaque_client_login_finish(login, invalid, 1, &upload, &session_key, &export_key) ==
               OPAQUE_SERIALIZATION_ERROR, "Malformed login response rejected");
        ASSERT(!upload.data && !session_key.data && !export_key.data, "Login failure publishes no outputs");
    }
}

// Exercises the exact client archive's WASM clock/entropy and opaque-handle
// lifecycle. Successful peer exchanges are covered by the private integration
// harness; this public test needs no server implementation or private keys.
void test_application_protocol(void) {
    TEST("Pinned application protocol refuses credentials before server proof");
    const uint8_t authority[] = "http://127.0.0.1:4200";
    const uint8_t public_key[32] = {9}; // X25519 base point, public test input.
    const uint8_t invalid_key[32] = {0};
    const uint8_t request[] = "{\"method\":\"POST\",\"target\":\"/auth/api/opaque-login-start\",\"body\":\"synthetic-credential\",\"cookie\":null,\"idempotency_key\":null}";
    ApplicationProtocol *first = NULL, *second = NULL;
    OpaqueResult bad = bs_protocol_start(authority, sizeof(authority) - 1, invalid_key, &first);
    ASSERT(bad.error != OPAQUE_SUCCESS && !first && !bad.buffer.data,
           "Invalid installation key publishes no handle or handshake");
    opaque_free_buffer(bad.buffer);
    OpaqueResult a = bs_protocol_start(authority, sizeof(authority) - 1, public_key, &first);
    OpaqueResult b = bs_protocol_start(authority, sizeof(authority) - 1, public_key, &second);
    ASSERT(a.error == OPAQUE_SUCCESS && b.error == OPAQUE_SUCCESS && first && second,
           "Pinned handshakes start with platform entropy and clock");
    ASSERT(a.buffer.len == 70 && b.buffer.len == 70 && a.buffer.data && b.buffer.data &&
           memcmp(a.buffer.data, "BH2.c.", 6) == 0 && memcmp(b.buffer.data, "BH2.c.", 6) == 0,
           "Handshake uses bounded body-only wire format");
    ASSERT(a.buffer.data && b.buffer.data && a.buffer.len == b.buffer.len &&
           memcmp(a.buffer.data, b.buffer.data, a.buffer.len) != 0,
           "Independent handshakes use fresh randomness");
    opaque_free_buffer(a.buffer);
    opaque_free_buffer(b.buffer);
    OpaqueResult sealed = bs_protocol_seal(first, request, sizeof(request) - 1);
    ASSERT(sealed.error != OPAQUE_SUCCESS && !sealed.buffer.data,
           "Credentials cannot be sealed before authenticated server proof");
    opaque_free_buffer(sealed.buffer);
    const uint8_t forged[] = "{\"success\":true}";
    ASSERT(bs_protocol_accept(second, forged, sizeof(forged) - 1) != OPAQUE_SUCCESS,
           "Forged plaintext handshake is rejected");
    sealed = bs_protocol_seal(second, request, sizeof(request) - 1);
    ASSERT(sealed.error != OPAQUE_SUCCESS && !sealed.buffer.data,
           "Failed handshake permanently closes the handle");
    opaque_free_buffer(sealed.buffer);
    OpaqueResult opened = bs_protocol_open(second, forged, sizeof(forged) - 1);
    ASSERT(opened.error != OPAQUE_SUCCESS && !opened.buffer.data,
           "Forged response cannot publish plaintext after failure");
    opaque_free_buffer(opened.buffer);
    bs_protocol_free(first);
    bs_protocol_free(second);
}

int main() {
    printf("╔════════════════════════════════════════════════════════════╗\n");
    printf("║  OPAQUE Client WASM FFI Test Suite                        ║\n");
    printf("╚════════════════════════════════════════════════════════════╝\n");

#ifdef __EMSCRIPTEN_PTHREADS__
    ASSERT(!emscripten_is_main_runtime_thread(), "Rust FFI suite executes on a real pthread");
#endif
    // Run tests
    test_registration_start();
    test_login_start();
    test_null_pointer_handling();
    test_empty_password();
    test_multiple_registrations();
    test_determinism();
    test_signing_vector();
    test_malformed_responses();
    test_application_protocol();

    // Print summary
    printf("\n╔════════════════════════════════════════════════════════════╗\n");
    printf("║  Test Summary                                              ║\n");
    printf("╚════════════════════════════════════════════════════════════╝\n");
    printf("  ✅ Passed: %d\n", tests_passed);
    printf("  ❌ Failed: %d\n", tests_failed);
    printf("  📊 Total:  %d\n", tests_passed + tests_failed);

    if (tests_failed == 0) {
        printf("\n🎉 All tests passed! WASM FFI is working correctly.\n\n");
        return 0;
    } else {
        printf("\n⚠️  Some tests failed. Please investigate.\n\n");
        return 1;
    }
}
