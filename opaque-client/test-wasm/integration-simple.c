/**
 * Simple WASM Integration Test for opaque-client
 *
 * This version only tests local OPAQUE functions (no HTTP).
 * Server integration is handled by Node.js wrapper (integration-node.cjs).
 *
 * Compile:
 *   emcc integration-simple.c ../target/wasm32-unknown-emscripten/release/libopaque_client.a \
 *        -o integration-simple.js \
 *        -s EXPORTED_FUNCTIONS='["_main","_malloc","_free"]' \
 *        -s EXPORTED_RUNTIME_METHODS='["ccall","cwrap","UTF8ToString","stringToUTF8","HEAP32","HEAPU8"]' \
 *        -s ALLOW_MEMORY_GROWTH=1 \
 *        -s INITIAL_MEMORY=67108864 \
 *        -s MODULARIZE=1 \
 *        -s EXPORT_NAME='createModule' \
 *        -s ENVIRONMENT=node
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Opaque types
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

typedef struct RegistrationState RegistrationState;
typedef struct LoginState LoginState;

// Rust FFI functions
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

// Test results
static int tests_passed = 0;
static int tests_failed = 0;

// Colors
#define COLOR_RESET   "\033[0m"
#define COLOR_RED     "\033[31m"
#define COLOR_GREEN   "\033[32m"
#define COLOR_YELLOW  "\033[33m"
#define COLOR_BLUE    "\033[34m"

#define LOG_INFO(msg, ...) printf(COLOR_BLUE "ℹ " COLOR_RESET msg "\n", ##__VA_ARGS__)
#define LOG_SUCCESS(msg, ...) printf(COLOR_GREEN "✓ " COLOR_RESET msg "\n", ##__VA_ARGS__)
#define LOG_ERROR(msg, ...) printf(COLOR_RED "✗ " COLOR_RESET msg "\n", ##__VA_ARGS__)
#define LOG_TEST(msg) printf("\n" COLOR_YELLOW "=== %s ===" COLOR_RESET "\n\n", msg)

static void print_hex(const char *label, const uint8_t *data, size_t len) {
    printf("  %s (%zu bytes): ", label, len);
    size_t display_len = (len > 32) ? 32 : len;
    for (size_t i = 0; i < display_len; i++) {
        printf("%02x", data[i]);
    }
    if (len > 32) printf("...");
    printf("\n");
}

// Wrapper functions for JS that return result via pointer instead of by value
// These make it much easier to call from JavaScript

int opaque_registration_start_wrapper(const char *password, size_t password_len,
                                       RegistrationState **state_out,
                                       uint8_t **request_data_out, size_t *request_len_out) {
    OpaqueResult result = opaque_client_registration_start(password, password_len, state_out);
    if (result.error == OPAQUE_SUCCESS) {
        *request_data_out = result.buffer.data;
        *request_len_out = result.buffer.len;
    }
    return result.error;
}

int opaque_login_start_wrapper(const char *password, size_t password_len,
                                LoginState **state_out,
                                uint8_t **request_data_out, size_t *request_len_out) {
    OpaqueResult result = opaque_client_login_start(password, password_len, state_out);
    if (result.error == OPAQUE_SUCCESS) {
        *request_data_out = result.buffer.data;
        *request_len_out = result.buffer.len;
    }
    return result.error;
}

// Helper to free buffer data returned from wrapper functions (for request/response buffers)
void opaque_free_buffer_data(uint8_t *data, size_t len) {
    OpaqueBuffer buffer = { .data = data, .len = len };
    opaque_free_buffer(buffer);
}

// Helper to free an OpaqueBuffer struct allocated on heap (for output buffers from login_finish)
void opaque_free_opaque_buffer(uint8_t *buffer_struct_ptr) {
    // OpaqueBuffer struct layout: [data ptr (8 bytes)][len (4 bytes)] = 12 bytes total
    // We need to free the data inside the struct, then free the struct itself
    OpaqueBuffer *buf = (OpaqueBuffer *)buffer_struct_ptr;
    if (buf && buf->data) {
        opaque_free_buffer(*buf);
    }
}

// Test OPAQUE login_start
static void test_login_start(const char *password) {
    LOG_TEST("OPAQUE Login Flow - Local Test");

    LoginState *state = NULL;
    OpaqueResult result = opaque_client_login_start(password, strlen(password), &state);

    if (result.error == OPAQUE_SUCCESS) {
        LOG_SUCCESS("Login started successfully");
        print_hex("Credential request", result.buffer.data, result.buffer.len);
        tests_passed++;

        // Cleanup
        opaque_free_buffer(result.buffer);
        if (state) opaque_free_login_state(state);
    } else {
        LOG_ERROR("Login start failed: error code %d", result.error);
        tests_failed++;
    }
}

// Main entry point
int main(int argc, char **argv) {
    printf("\n");
    printf("╔════════════════════════════════════════════════════════════╗\n");
    printf("║  OPAQUE Client WASM Integration Test                      ║\n");
    printf("╚════════════════════════════════════════════════════════════╝\n");
    printf("\n");

    // Run local tests
    const char *test_password = "test_password_123";
    test_login_start(test_password);

    // Print summary
    printf("\n");
    printf("╔════════════════════════════════════════════════════════════╗\n");
    printf("║  Test Summary                                              ║\n");
    printf("╚════════════════════════════════════════════════════════════╝\n");
    printf("  " COLOR_GREEN "✓" COLOR_RESET " Passed: %d\n", tests_passed);
    printf("  " COLOR_RED "✗" COLOR_RESET " Failed: %d\n", tests_failed);
    printf("  📊 Total:  %d\n", tests_passed + tests_failed);
    printf("\n");

    if (tests_failed == 0) {
        printf(COLOR_GREEN "🎉 All tests passed! WASM build is working correctly." COLOR_RESET "\n\n");
        return 0;
    } else {
        printf(COLOR_RED "⚠️  Some tests failed. Please investigate." COLOR_RESET "\n\n");
        return 1;
    }
}
