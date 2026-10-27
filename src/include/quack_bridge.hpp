//===----------------------------------------------------------------------===//
//                         DuckDB / Boilstream
//
// quack_bridge.hpp
//
// Opaque structured-capability bridge between Quack and the Boilstream host.
// C++ owns the immutable host-verified capability context but never interprets
// product grants, display names, access modes, or storage-owner scope.
//===----------------------------------------------------------------------===//

#pragma once

#include "duckdb.hpp"
#include "quack_tenant_session_quota.hpp"
#include "duckdb/main/extension/extension_loader.hpp"

#include <cstddef>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>

extern "C" {

//! Factory has static lifetime. Create returns null on denial; destroy is
//! no-throw and releases exactly one context after its last callback borrower.
//! Context internals and permission semantics remain entirely Rust-owned.
struct boilstream_quack_capability_context_factory {
	const void *(*create)(const char *capability_bundle);
	void (*destroy)(const void *context);
};
void boilstream_quack_set_capability_context_factory(const boilstream_quack_capability_context_factory *factory);

//! V2 keeps requester identity and quota policy paired with the context factory.
//! requester_tenant returns zero on denial; limit is host policy, not wire input.
struct boilstream_quack_capability_context_factory_v2 {
	const void *(*create)(const char *capability_bundle);
	void (*destroy)(const void *context);
	uint32_t (*requester_tenant)(const void *context);
	uint32_t max_sessions_per_tenant;
};
void boilstream_quack_set_capability_context_factory_v2(const boilstream_quack_capability_context_factory_v2 *factory);

//! Verify a Quack JWT and return the requester audit identity plus one opaque,
//! versioned capability bundle. Returns 1 on success and 0 on denial.
typedef int (*boilstream_quack_jwt_verifier_fn)(const char *jwt, size_t jwt_len, char *user_id_out,
                                                size_t user_id_capacity, char *capability_bundle_out,
                                                size_t capability_bundle_capacity);
void boilstream_quack_set_jwt_verifier(boilstream_quack_jwt_verifier_fn fn);

//! Trusted SQL planner. The Rust host parses exactly one statement, resolves
//! aliases to canonical catalog UUID, may select an opaque execution catalog,
//! and may rewrite SQL for Airport routing. The execution target is independent
//! of whether SQL is rewritten. Returns 1 for rewrite, 0 for no rewrite, and
//! <0 for hard denial.
typedef int (*boilstream_quack_catalog_planner_fn)(const void *capability_context, const char *declared_catalog_id,
                                                   const char *sql_in, uint32_t *operation_out, char *catalog_id_out,
                                                   size_t catalog_id_out_size, char *execution_catalog_alias_out,
                                                   size_t execution_catalog_alias_out_size,
                                                   char *read_catalog_alias_out, size_t read_catalog_alias_out_size,
                                                   char *sql_out_buf, size_t sql_out_size, char *error_out_buf,
                                                   size_t error_out_size);
void boilstream_quack_set_catalog_planner(boilstream_quack_catalog_planner_fn fn);

//! Typed data-plane authorizer. The execution alias is an opaque target selected
//! by the trusted planner; request SQL and display names are deliberately absent.
//! Catalog operations return the authoritative storage-owner tenant for
//! physical routing. Returns 0 on allow and nonzero on hard denial.
typedef int (*boilstream_quack_catalog_authorizer_fn)(const void *capability_context, uint32_t operation,
                                                      const char *catalog_id, const char *execution_catalog_alias,
                                                      const char *read_catalog_alias,
                                                      uint32_t *storage_owner_tenant_id_out, char *error_out_buf,
                                                      size_t error_out_size);
void boilstream_quack_set_catalog_authorizer(boilstream_quack_catalog_authorizer_fn fn);

//! Post-success durability hook addressed by canonical UUID and typed
//! operation. Returns 0 on success/no-op and nonzero on failure.
typedef int (*boilstream_quack_post_execute_fn)(const void *capability_context, uint32_t operation,
                                                const char *catalog_id, char *error_out_buf, size_t error_out_size);
void boilstream_quack_set_post_execute_hook(boilstream_quack_post_execute_fn fn);

//! Opaque session adapters installed into Quack at extension load.
int boilstream_quack_catalog_plan(const char *session_id, const char *declared_catalog_id, const char *sql_in,
                                  uint32_t *operation_out, char *catalog_id_out, size_t catalog_id_out_size,
                                  char *execution_catalog_alias_out, size_t execution_catalog_alias_out_size,
                                  char *read_catalog_alias_out, size_t read_catalog_alias_out_size, char *sql_out_buf,
                                  size_t sql_out_size, char *error_out_buf, size_t error_out_size);
int boilstream_quack_catalog_authorize(const char *session_id, uint32_t operation, const char *catalog_id,
                                       const char *execution_catalog_alias, const char *read_catalog_alias,
                                       uint32_t *storage_owner_tenant_id_out, char *error_out_buf,
                                       size_t error_out_size);
int boilstream_quack_catalog_post_execute(const char *session_id, uint32_t operation, const char *catalog_id,
                                          char *error_out_buf, size_t error_out_size);
void boilstream_quack_catalog_session_close(const char *session_id);
void *boilstream_quack_session_begin(const char *session_id);
// Consumes owner exactly once: 1 commits, every other outcome rolls back.
void boilstream_quack_session_finish(void *owner, uint32_t outcome);

} // extern "C"

namespace duckdb {

struct SessionCtx {
	std::string user_id;
	// Release quota after the authority destructor has completed.
	std::shared_ptr<QuackTenantSessionQuota::Lease> session_quota;
	std::shared_ptr<const void> capability_context;
};

//! A retained immutable session lease. No callback or destruction runs under
//! the registry lock; close/replacement cannot invalidate an admitted borrower.
std::shared_ptr<const SessionCtx> GetQuackSessionCtx(const std::string &session_id);
void RegisterQuackBridge(ExtensionLoader &loader);

} // namespace duckdb
