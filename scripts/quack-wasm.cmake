# Applied only to the isolated, pinned Quack dependency build. Host is unchanged.
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fwasm-exceptions -pthread -DWITH_WASM_THREADS=1 -DWITH_WASM_SIMD=1 -DWITH_WASM_BULK_MEMORY=1 -DWEBDB_FAST_EXCEPTIONS=1")
string(SUBSTRING "${BOILSTREAM_QUACK_REVISION}" 0 10 QUACK_VERSION)
duckdb_extension_load(quack
    EXTENSION_VERSION ${QUACK_VERSION}
    SOURCE_DIR ${BOILSTREAM_QUACK_SOURCE}
    LINKED_LIBS "${BOILSTREAM_QUACK_OPENSSL}/lib/libssl.a ${BOILSTREAM_QUACK_OPENSSL}/lib/libcrypto.a"
)
