//===----------------------------------------------------------------------===//
//                         DuckDB
//
// boilstream_c_api.cpp - C API implementation for WASM
//
//===----------------------------------------------------------------------===//

#define DUCKDB_EXTENSION_NAME boilstream

#include "duckdb_extension.h"
#include <stdio.h>

#ifdef __EMSCRIPTEN__
#include <emscripten.h>
#define BOILSTREAM_LOG(msg) EM_ASM({ console.log("[BOILSTREAM C API] " + UTF8ToString($0)); }, msg)
#else
#define BOILSTREAM_LOG(msg) fprintf(stderr, "[BOILSTREAM C API] %s\n", msg)
#endif

// Declare the C API entrypoint
// The DUCKDB_EXTENSION_ENTRYPOINT macro creates:
// 1. An internal function: boilstream_init_c_api_internal(connection, info, access)
// 2. An exported function: boilstream_init_c_api(info, access) that opens a connection
DUCKDB_EXTENSION_ENTRYPOINT
(duckdb_connection connection, duckdb_extension_info info, struct duckdb_extension_access *access) {
	BOILSTREAM_LOG("C API entrypoint called!");

	// Test if we can call C API functions
	// Use the macro names directly (they expand to duckdb_ext_api.function_name)
	const char *version = duckdb_library_version();
	if (version) {
		char msg[256];
		snprintf(msg, sizeof(msg), "DuckDB version: %s", version);
		BOILSTREAM_LOG(msg);
	} else {
		BOILSTREAM_LOG("Warning: duckdb_library_version() returned NULL");
	}

	BOILSTREAM_LOG("Extension loaded successfully via C API");
	return true;
}
