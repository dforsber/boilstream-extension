#include "quack_bridge.hpp"

#include "duckdb/common/types/string_type.hpp"
#include "duckdb/common/types/vector.hpp"
#include "duckdb/common/vector_operations/binary_executor.hpp"
#include "duckdb/common/vector_operations/ternary_executor.hpp"
#include "duckdb/function/scalar_function.hpp"

#include <atomic>
#include <cstring>
#include <vector>

#ifdef _WIN32
#include <windows.h>
static inline void *boilstream_lookup_runtime_symbol(const char *name) {
	HMODULE handle = ::GetModuleHandleA(nullptr);
	return handle ? reinterpret_cast<void *>(::GetProcAddress(handle, name)) : nullptr;
}
#else
#include <dlfcn.h>
static inline void *boilstream_lookup_runtime_symbol(const char *name) {
	return ::dlsym(RTLD_DEFAULT, name);
}
#endif

namespace {

std::atomic<boilstream_quack_jwt_verifier_fn> &JwtVerifierSlot() {
	static std::atomic<boilstream_quack_jwt_verifier_fn> slot {nullptr};
	return slot;
}

std::atomic<boilstream_quack_catalog_planner_fn> &CatalogPlannerSlot() {
	static std::atomic<boilstream_quack_catalog_planner_fn> slot {nullptr};
	return slot;
}

std::atomic<boilstream_quack_catalog_authorizer_fn> &CatalogAuthorizerSlot() {
	static std::atomic<boilstream_quack_catalog_authorizer_fn> slot {nullptr};
	return slot;
}

std::atomic<boilstream_quack_post_execute_fn> &PostExecuteSlot() {
	static std::atomic<boilstream_quack_post_execute_fn> slot {nullptr};
	return slot;
}

void WriteError(char *buf, size_t size, const char *message) {
	if (!buf || size == 0) {
		return;
	}
	std::strncpy(buf, message, size - 1);
	buf[size - 1] = '\0';
}

} // namespace

extern "C" void boilstream_quack_set_jwt_verifier(boilstream_quack_jwt_verifier_fn fn) {
	JwtVerifierSlot().store(fn, std::memory_order_release);
}

extern "C" void boilstream_quack_set_catalog_planner(boilstream_quack_catalog_planner_fn fn) {
	CatalogPlannerSlot().store(fn, std::memory_order_release);
}

extern "C" void boilstream_quack_set_catalog_authorizer(boilstream_quack_catalog_authorizer_fn fn) {
	CatalogAuthorizerSlot().store(fn, std::memory_order_release);
}

extern "C" void boilstream_quack_set_post_execute_hook(boilstream_quack_post_execute_fn fn) {
	PostExecuteSlot().store(fn, std::memory_order_release);
}

typedef void (*quack_set_catalog_admission_hooks_fn_t)(
    int (*planner)(const char *, const char *, const char *, uint32_t *, char *, size_t, char *, size_t, char *,
                   size_t),
    int (*authorizer)(const char *, uint32_t, const char *, uint32_t *, char *, size_t),
    void (*session_close)(const char *));
typedef void (*quack_set_post_execute_hook_fn_t)(int (*hook)(const char *, uint32_t, const char *, char *, size_t));

namespace duckdb {
namespace {

std::mutex &SessionMapMutex() {
	static std::mutex mutex;
	return mutex;
}

std::unordered_map<std::string, SessionCtx> &SessionMap() {
	static std::unordered_map<std::string, SessionCtx> sessions;
	return sessions;
}

void BoilstreamQuackAuthnFunction(DataChunk &args, ExpressionState &, Vector &result) {
	auto verifier = JwtVerifierSlot().load(std::memory_order_acquire);
	TernaryExecutor::Execute<string_t, string_t, string_t, bool>(
	    args.data[0], args.data[1], args.data[2], result, args.size(),
	    [verifier](string_t sid, string_t client_auth, string_t) {
		    try {
			    if (!verifier) {
				    return false;
			    }
			    const std::string session_id(sid.GetData(), sid.GetSize());
			    if (session_id.empty()) {
				    return false;
			    }
			    char user_id[128] = {};
			    constexpr size_t BUNDLE_CAPACITY = 64ULL * 1024;
			    std::vector<char> bundle(BUNDLE_CAPACITY, '\0');
			    const auto rc = verifier(client_auth.GetData(), client_auth.GetSize(), user_id, sizeof(user_id),
			                             bundle.data(), bundle.size());
			    user_id[sizeof(user_id) - 1] = '\0';
			    bundle.back() = '\0';
			    if (rc != 1 || user_id[0] == '\0' || bundle[0] == '\0') {
				    return false;
			    }
			    SessionCtx context;
			    context.user_id = user_id;
			    context.capability_bundle = bundle.data();
			    std::lock_guard<std::mutex> guard(SessionMapMutex());
			    SessionMap()[session_id] = std::move(context);
			    return true;
		    } catch (...) {
			    return false;
		    }
	    });
}

// Authentication binds the opaque bundle. This scalar only verifies that the
// same session exists; all operation authorization happens at the typed hook.
void BoilstreamQuackAuthzFunction(DataChunk &args, ExpressionState &, Vector &result) {
	BinaryExecutor::Execute<string_t, string_t, bool>(
	    args.data[0], args.data[1], result, args.size(), [](string_t sid, string_t) {
		    try {
			    return GetQuackSessionCtx(std::string(sid.GetData(), sid.GetSize())).second;
		    } catch (...) {
			    return false;
		    }
	    });
}

void BoilstreamQuackDebugSessionCountFunction(DataChunk &args, ExpressionState &, Vector &result) {
	D_ASSERT(args.ColumnCount() == 0);
	std::lock_guard<std::mutex> guard(SessionMapMutex());
	result.SetVectorType(VectorType::CONSTANT_VECTOR);
	ConstantVector::GetData<int32_t>(result)[0] = static_cast<int32_t>(SessionMap().size());
}

} // namespace

std::pair<SessionCtx, bool> GetQuackSessionCtx(const std::string &session_id) {
	std::lock_guard<std::mutex> guard(SessionMapMutex());
	auto found = SessionMap().find(session_id);
	if (found == SessionMap().end()) {
		return {SessionCtx {}, false};
	}
	return {found->second, true};
}

void RegisterQuackBridge(ExtensionLoader &loader) {
	loader.RegisterFunction(ScalarFunction("boilstream_quack_authn",
	                                       {LogicalType::VARCHAR, LogicalType::VARCHAR, LogicalType::VARCHAR},
	                                       LogicalType::BOOLEAN, BoilstreamQuackAuthnFunction));
	loader.RegisterFunction(ScalarFunction("boilstream_quack_authz", {LogicalType::VARCHAR, LogicalType::VARCHAR},
	                                       LogicalType::BOOLEAN, BoilstreamQuackAuthzFunction));
	loader.RegisterFunction(ScalarFunction("boilstream_quack_debug_session_count", {}, LogicalType::INTEGER,
	                                       BoilstreamQuackDebugSessionCountFunction));
	auto admission_setter = reinterpret_cast<quack_set_catalog_admission_hooks_fn_t>(
	    boilstream_lookup_runtime_symbol("quack_set_catalog_admission_hooks"));
	auto post_setter = reinterpret_cast<quack_set_post_execute_hook_fn_t>(
	    boilstream_lookup_runtime_symbol("quack_set_post_execute_hook"));
	if (admission_setter) {
		admission_setter(&boilstream_quack_catalog_plan, &boilstream_quack_catalog_authorize,
		                 &boilstream_quack_catalog_session_close);
	}
	if (post_setter) {
		post_setter(&boilstream_quack_catalog_post_execute);
	}
}

} // namespace duckdb

extern "C" void boilstream_quack_catalog_session_close(const char *session_id) {
	if (!session_id) {
		return;
	}
	try {
		std::lock_guard<std::mutex> guard(duckdb::SessionMapMutex());
		duckdb::SessionMap().erase(session_id);
	} catch (...) {
		// Quack teardown callbacks are no-throw and idempotent.
	}
}

extern "C" int boilstream_quack_catalog_plan(const char *session_id, const char *declared_catalog_id,
                                             const char *sql_in, uint32_t *operation_out, char *catalog_id_out,
                                             size_t catalog_id_out_size, char *sql_out_buf, size_t sql_out_size,
                                             char *error_out_buf, size_t error_out_size) {
	try {
		if (!session_id || !declared_catalog_id || !sql_in || !operation_out || !catalog_id_out ||
		    catalog_id_out_size == 0 || !sql_out_buf || sql_out_size == 0 || !error_out_buf || error_out_size == 0) {
			WriteError(error_out_buf, error_out_size, "Catalog planner received invalid buffers");
			return -1;
		}
		auto planner = CatalogPlannerSlot().load(std::memory_order_acquire);
		if (!planner) {
			WriteError(error_out_buf, error_out_size, "Catalog planner is not registered");
			return -1;
		}
		auto session = duckdb::GetQuackSessionCtx(session_id);
		if (!session.second) {
			WriteError(error_out_buf, error_out_size, "Quack session capability bundle is missing");
			return -1;
		}
		return planner(session.first.capability_bundle.c_str(), declared_catalog_id, sql_in, operation_out,
		               catalog_id_out, catalog_id_out_size, sql_out_buf, sql_out_size, error_out_buf, error_out_size);
	} catch (...) {
		WriteError(error_out_buf, error_out_size, "Catalog planner bridge failed");
		return -1;
	}
}

extern "C" int boilstream_quack_catalog_authorize(const char *session_id, uint32_t operation, const char *catalog_id,
                                                  uint32_t *storage_owner_tenant_id_out, char *error_out_buf,
                                                  size_t error_out_size) {
	try {
		if (storage_owner_tenant_id_out) {
			*storage_owner_tenant_id_out = 0;
		}
		if (!session_id || !catalog_id || !storage_owner_tenant_id_out || !error_out_buf || error_out_size == 0) {
			WriteError(error_out_buf, error_out_size, "Catalog authorizer received invalid buffers");
			return -1;
		}
		auto authorizer = CatalogAuthorizerSlot().load(std::memory_order_acquire);
		if (!authorizer) {
			WriteError(error_out_buf, error_out_size, "Catalog authorizer is not registered");
			return -1;
		}
		auto session = duckdb::GetQuackSessionCtx(session_id);
		if (!session.second) {
			WriteError(error_out_buf, error_out_size, "Quack session capability bundle is missing");
			return -1;
		}
		const auto rc = authorizer(session.first.capability_bundle.c_str(), operation, catalog_id,
		                           storage_owner_tenant_id_out, error_out_buf, error_out_size);
		if (rc != 0) {
			*storage_owner_tenant_id_out = 0;
		}
		return rc;
	} catch (...) {
		if (storage_owner_tenant_id_out) {
			*storage_owner_tenant_id_out = 0;
		}
		WriteError(error_out_buf, error_out_size, "Catalog authorizer bridge failed");
		return -1;
	}
}

extern "C" int boilstream_quack_catalog_post_execute(const char *session_id, uint32_t operation, const char *catalog_id,
                                                     char *error_out_buf, size_t error_out_size) {
	try {
		if (!session_id || !catalog_id || !error_out_buf || error_out_size == 0) {
			WriteError(error_out_buf, error_out_size, "Post-execute hook received invalid buffers");
			return -1;
		}
		auto hook = PostExecuteSlot().load(std::memory_order_acquire);
		if (!hook) {
			return 0;
		}
		auto session = duckdb::GetQuackSessionCtx(session_id);
		if (!session.second) {
			WriteError(error_out_buf, error_out_size, "Quack session capability bundle is missing");
			return -1;
		}
		return hook(session.first.capability_bundle.c_str(), operation, catalog_id, error_out_buf, error_out_size);
	} catch (...) {
		WriteError(error_out_buf, error_out_size, "Post-execute bridge failed");
		return -1;
	}
}
