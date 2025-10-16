# This file is included by DuckDB's build system. It specifies which extension to load

# WASM: Prepend wasm-opt wrapper to PATH to filter deprecated flags
if(EMSCRIPTEN OR CMAKE_SYSTEM_NAME STREQUAL "Emscripten")
    set(WASM_OPT_WRAPPER_DIR "${CMAKE_CURRENT_LIST_DIR}/scripts")
    if(EXISTS "${WASM_OPT_WRAPPER_DIR}/wasm-opt")
        set(ENV{PATH} "${WASM_OPT_WRAPPER_DIR}:$ENV{PATH}")
        message(STATUS "WASM: Using wasm-opt wrapper from ${WASM_OPT_WRAPPER_DIR}")
    endif()
endif()

# Extension from this repo
duckdb_extension_load(boilstream
    SOURCE_DIR ${CMAKE_CURRENT_LIST_DIR}
    LOAD_TESTS
    REQUIRES httpfs
    LINKED_LIBS "${CMAKE_CURRENT_LIST_DIR}/opaque-client/target/wasm32-unknown-emscripten/release/libopaque_client.a"
)

# Any extra extensions that should be built
# e.g.: duckdb_extension_load(json)