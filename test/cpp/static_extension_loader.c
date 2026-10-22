// Static extension loader for the C++ test executables (DuckDB >= 2.0).
//
// Since DuckDB 2.0 a program that links extension archives into libduckdb_static.a has to register them itself:
// duckdb_register_static_extensions names each extension's describe function, which also pulls the extension out of
// its archive. This mirrors what DuckDB's build generates from extension/loader/static_extension_loader.c.in for its
// own executables, for the archives test/cpp/CMakeLists.txt links. It is compiled into every test program together
// with extension/loader/static_extension_autoregister.cpp, which calls it before main.

#include "duckdb_static_extension.h"

#ifdef __cplusplus
extern "C" {
#endif

int32_t duckdb_extension_boilstream_describe(duckdb_extension_descriptor *descriptor);
int32_t duckdb_extension_parquet_describe(duckdb_extension_descriptor *descriptor);
int32_t duckdb_extension_core_functions_describe(duckdb_extension_descriptor *descriptor);

int32_t duckdb_register_static_extensions(void) {
	int32_t result = 0;
	if (duckdb_register_static_extension(duckdb_extension_boilstream_describe) != 0) {
		result = 1;
	}
	if (duckdb_register_static_extension(duckdb_extension_parquet_describe) != 0) {
		result = 1;
	}
	if (duckdb_register_static_extension(duckdb_extension_core_functions_describe) != 0) {
		result = 1;
	}
	return result;
}

#ifdef __cplusplus
}
#endif
