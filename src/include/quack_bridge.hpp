//===----------------------------------------------------------------------===//
//                         DuckDB / Boilstream
//
// quack_bridge.hpp
//
// Opaque structured-capability bridge between Quack and the Boilstream host.
// C++ stores the signed, host-verified capability bundle but never interprets
// product grants, display names, access modes, or storage-owner scope.
//===----------------------------------------------------------------------===//

#pragma once

#include "duckdb.hpp"
#include "duckdb/main/extension/extension_loader.hpp"

#include <cstddef>
#include <mutex>
#include <string>
#include <unordered_map>

extern "C" {

//! Verify a Quack JWT and return the requester audit identity plus one opaque,
//! versioned capability bundle. Returns 1 on success and 0 on denial.
typedef int (*boilstream_quack_jwt_verifier_fn)(const char *jwt, size_t jwt_len, char *user_id_out,
                                                size_t user_id_capacity, char *capability_bundle_out,
                                                size_t capability_bundle_capacity);
void boilstream_quack_set_jwt_verifier(boilstream_quack_jwt_verifier_fn fn);

//! Trusted SQL planner. The Rust host parses exactly one statement, resolves
//! aliases to canonical catalog UUID, and may rewrite SQL for Airport routing.
//! Returns 1 for rewrite, 0 for no rewrite, and <0 for hard denial.
typedef int (*boilstream_quack_catalog_planner_fn)(const char *capability_bundle, const char *declared_catalog_id,
                                                   const char *sql_in, uint32_t *operation_out, char *catalog_id_out,
                                                   size_t catalog_id_out_size, char *sql_out_buf, size_t sql_out_size,
                                                   char *error_out_buf, size_t error_out_size);
void boilstream_quack_set_catalog_planner(boilstream_quack_catalog_planner_fn fn);

//! Typed data-plane authorizer. SQL and display names are deliberately absent.
//! Returns 0 on allow and nonzero on hard denial.
typedef int (*boilstream_quack_catalog_authorizer_fn)(const char *capability_bundle, uint32_t operation,
                                                      const char *catalog_id, char *error_out_buf,
                                                      size_t error_out_size);
void boilstream_quack_set_catalog_authorizer(boilstream_quack_catalog_authorizer_fn fn);

//! Post-success durability hook addressed by canonical UUID and typed
//! operation. Returns 0 on success/no-op and nonzero on failure.
typedef int (*boilstream_quack_post_execute_fn)(const char *capability_bundle, uint32_t operation,
                                                const char *catalog_id, char *error_out_buf, size_t error_out_size);
void boilstream_quack_set_post_execute_hook(boilstream_quack_post_execute_fn fn);

//! Opaque session adapters installed into Quack at extension load.
int boilstream_quack_catalog_plan(const char *session_id, const char *declared_catalog_id, const char *sql_in,
                                  uint32_t *operation_out, char *catalog_id_out, size_t catalog_id_out_size,
                                  char *sql_out_buf, size_t sql_out_size, char *error_out_buf, size_t error_out_size);
int boilstream_quack_catalog_authorize(const char *session_id, uint32_t operation, const char *catalog_id,
                                       char *error_out_buf, size_t error_out_size);
int boilstream_quack_catalog_post_execute(const char *session_id, uint32_t operation, const char *catalog_id,
                                          char *error_out_buf, size_t error_out_size);
void boilstream_quack_catalog_session_close(const char *session_id);

} // extern "C"

namespace duckdb {

struct SessionCtx {
	std::string user_id;
	std::string capability_bundle;
};

std::pair<SessionCtx, bool> GetQuackSessionCtx(const std::string &session_id);
void RegisterQuackBridge(ExtensionLoader &loader);

} // namespace duckdb
