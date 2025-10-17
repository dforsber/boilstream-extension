# This file is included by DuckDB's build system. It specifies which extension to load

# Extension from this repo
duckdb_extension_load(boilstream
    SOURCE_DIR ${CMAKE_CURRENT_LIST_DIR}
    LOAD_TESTS
    REQUIRES httpfs
    LINKED_LIBS "${CMAKE_CURRENT_LIST_DIR}/opaque-client/target/wasm32-unknown-emscripten/release/libopaque_client.a"
)

# Any extra extensions that should be built
# e.g.: duckdb_extension_load(json)