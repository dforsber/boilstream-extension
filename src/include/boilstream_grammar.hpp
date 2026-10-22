//===----------------------------------------------------------------------===//
//                         DuckDB
//
// boilstream_grammar.hpp
//
// First-class SQL syntax for the BoilStream PRAGMA commands (DuckDB >= 2.0 PEG
// grammar extension). Each statement is transformed into the PragmaStatement
// that the corresponding PRAGMA boilstream_* call would have produced.
//
//===----------------------------------------------------------------------===//

#pragma once

#include "duckdb/main/extension/extension_loader.hpp"

namespace duckdb {

//! Name of the grammar extension, as listed in duckdb_grammar_extensions() and
//! accepted by SET active_grammar_extensions = ['boilstream'].
constexpr const char *BOILSTREAM_GRAMMAR_NAME = "boilstream";

//! Register the grammar extension and the per-connection activation callback.
void RegisterBoilstreamGrammar(ExtensionLoader &loader);

} // namespace duckdb
