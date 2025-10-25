/**
 * Simple C test program for opaque-client WASM FFI
 *
 * This program can be compiled with emcc to create a standalone WASM test
 * that verifies the Rust FFI functions work correctly.
 *
 * Compile:
 *   emcc test-ffi.c ../target/wasm32-unknown-emscripten/release/libopaque_client.a \
 *        -o test-ffi.html -s EXPORTED_FUNCTIONS='["_main"]' -s EXPORTED_RUNTIME_METHODS='["ccall","cwrap"]'
 *
 * Run:
 *   emrun test-ffi.html
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Include the opaque-client C header
// In a real build, this would be in your include path
typedef enum {
    OPAQUE_SUCCESS = 0,
    OPAQUE_INVALID_INPUT = 1,
    OPAQUE_PROTOCOL_ERROR = 2,
    OPAQUE_SERIALIZATION_ERROR = 3,
    OPAQUE_MEMORY_ERROR = 4,
} OpaqueError;

typedef struct {
    uint8_t *data;
    size_t len;
} OpaqueBuffer;

typedef struct {
    OpaqueError error;
    OpaqueBuffer buffer;
} OpaqueResult;

// Forward declarations for opaque types
typedef struct RegistrationState RegistrationState;
typedef struct LoginState LoginState;

// Function declarations (these are provided by the Rust library)
extern OpaqueResult opaque_client_registration_start(const char *password, size_t password_len, RegistrationState **state_out);
extern OpaqueError opaque_client_registration_finish(RegistrationState *state, const uint8_t *registration_response,
                                                      size_t registration_response_len, OpaqueBuffer *upload_out,
                                                      OpaqueBuffer *export_key_out);
extern OpaqueResult opaque_client_login_start(const char *password, size_t password_len, LoginState **state_out);
extern OpaqueError opaque_client_login_finish(LoginState *state, const uint8_t *credential_response,
                                               size_t credential_response_len, OpaqueBuffer *finalization_out,
                                               OpaqueBuffer *session_key_out, OpaqueBuffer *export_key_out);
extern void opaque_free_buffer(OpaqueBuffer buffer);
extern void opaque_free_registration_state(RegistrationState *state);
extern void opaque_free_login_state(LoginState *state);

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
    ASSERT(result.buffer.len > 0, "Registration request has non-zero length");

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
    ASSERT(result.buffer.len > 0, "Credential request has non-zero length");

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
    ASSERT(result.error == OPAQUE_SUCCESS || result.error == OPAQUE_INVALID_INPUT,
           "Empty password handling is consistent");

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
    if (result1.buffer.len == result2.buffer.len) {
        are_different = memcmp(result1.buffer.data, result2.buffer.data, result1.buffer.len) != 0;
    } else {
        are_different = 1;
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

int main() {
    printf("╔════════════════════════════════════════════════════════════╗\n");
    printf("║  OPAQUE Client WASM FFI Test Suite                        ║\n");
    printf("╚════════════════════════════════════════════════════════════╝\n");

    // Run tests
    test_registration_start();
    test_login_start();
    test_null_pointer_handling();
    test_empty_password();
    test_multiple_registrations();
    test_determinism();

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
