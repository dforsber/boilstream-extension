#include "quack_bridge.hpp"
#include "quack_session_admission_registry.hpp"

#include "duckdb/common/types/string_type.hpp"
#include "duckdb/common/types/vector.hpp"
#include "duckdb/common/vector_operations/binary_executor.hpp"
#include "duckdb/common/vector_operations/ternary_executor.hpp"
#include "duckdb/function/scalar_function.hpp"
#ifdef BOILSTREAM_HAS_QUERY_ERROR_PRIVACY
// Fork-only: the privacy API and the completeness-reporting tokenizer the classifier needs.
#include "duckdb/main/extension_callback_manager.hpp"
#include "boilstream_diagnostics.hpp"
#include "boilstream_query_privacy.hpp"
#endif

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

std::atomic<const boilstream_quack_capability_context_factory *> &ContextFactorySlot() {
	static std::atomic<const boilstream_quack_capability_context_factory *> slot {nullptr};
	return slot;
}

std::atomic<const boilstream_quack_capability_context_factory_v2 *> &ContextFactoryV2Slot() {
	static std::atomic<const boilstream_quack_capability_context_factory_v2 *> slot{nullptr};
	return slot;
}

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

void ClearBuffer(char *buf, size_t size) noexcept {
	if (buf && size > 0) {
		buf[0] = '\0';
	}
}

void ClearCatalogPlanDataOutputs(uint32_t *operation_out, char *catalog_id_out, size_t catalog_id_out_size,
                                 char *execution_catalog_alias_out, size_t execution_catalog_alias_out_size,
                                 char *read_catalog_alias_out, size_t read_catalog_alias_out_size, char *sql_out_buf,
                                 size_t sql_out_size) noexcept {
	if (operation_out) {
		*operation_out = 0;
	}
	ClearBuffer(catalog_id_out, catalog_id_out_size);
	ClearBuffer(execution_catalog_alias_out, execution_catalog_alias_out_size);
	ClearBuffer(read_catalog_alias_out, read_catalog_alias_out_size);
	ClearBuffer(sql_out_buf, sql_out_size);
}

} // namespace

namespace duckdb {
//! Installs the fail-closed admission hooks into Quack once the Rust host has registered a planner.
void InstallQuackAdmissionHooksIfHosted();
} // namespace duckdb

extern "C" void
boilstream_quack_set_capability_context_factory(const boilstream_quack_capability_context_factory *factory) {
	ContextFactoryV2Slot().store(nullptr, std::memory_order_release);
	ContextFactorySlot().store(factory, std::memory_order_release);
}

extern "C" void
boilstream_quack_set_capability_context_factory_v2(const boilstream_quack_capability_context_factory_v2 *factory) {
	ContextFactorySlot().store(nullptr, std::memory_order_release);
	ContextFactoryV2Slot().store(factory, std::memory_order_release);
}

extern "C" void boilstream_quack_set_jwt_verifier(boilstream_quack_jwt_verifier_fn fn) {
	JwtVerifierSlot().store(fn, std::memory_order_release);
}

extern "C" void boilstream_quack_set_catalog_planner(boilstream_quack_catalog_planner_fn fn) {
	CatalogPlannerSlot().store(fn, std::memory_order_release);
	duckdb::InstallQuackAdmissionHooksIfHosted();
}

extern "C" void boilstream_quack_set_catalog_authorizer(boilstream_quack_catalog_authorizer_fn fn) {
	CatalogAuthorizerSlot().store(fn, std::memory_order_release);
	duckdb::InstallQuackAdmissionHooksIfHosted();
}

extern "C" void boilstream_quack_set_post_execute_hook(boilstream_quack_post_execute_fn fn) {
	PostExecuteSlot().store(fn, std::memory_order_release);
	duckdb::InstallQuackAdmissionHooksIfHosted();
}

typedef void (*quack_set_catalog_admission_hooks_fn_t)(decltype(&boilstream_quack_catalog_plan) planner,
                                                       decltype(&boilstream_quack_catalog_authorize) authorizer,
                                                       void (*session_close)(const char *));
typedef void (*quack_set_catalog_admission_hooks_v2_fn_t)(decltype(&boilstream_quack_catalog_plan),
    decltype(&boilstream_quack_catalog_authorize), decltype(&boilstream_quack_catalog_session_close),
    decltype(&boilstream_quack_session_begin), decltype(&boilstream_quack_session_finish));
typedef void (*quack_set_catalog_admission_hooks_v3_fn_t)(decltype(&boilstream_quack_catalog_plan),
    decltype(&boilstream_quack_catalog_authorize), decltype(&boilstream_quack_catalog_session_close),
    decltype(&boilstream_quack_session_begin), decltype(&boilstream_quack_session_finish),
    decltype(&boilstream_quack_session_requester_tenant));
typedef void (*quack_set_post_execute_hook_fn_t)(int (*hook)(const char *, uint32_t, const char *, char *, size_t));

namespace duckdb {
namespace {

struct QuackHookSetterSlots {
	std::atomic<quack_set_catalog_admission_hooks_fn_t> admission {nullptr};
	std::atomic<quack_set_catalog_admission_hooks_v2_fn_t> admission_v2 {nullptr};
	std::atomic<quack_set_catalog_admission_hooks_v3_fn_t> admission_v3 {nullptr};
	std::atomic<quack_set_post_execute_hook_fn_t> post_execute {nullptr};
	std::atomic<bool> installed {false};
};

QuackHookSetterSlots &QuackHookSetters() {
	static auto *slots = new QuackHookSetterSlots();
	return *slots;
}

// Databases that loaded the extension before a host registered; the host may arrive later.
struct LoadedDatabases {
	std::mutex mutex;
	std::vector<weak_ptr<DatabaseInstance>> databases;
};

LoadedDatabases &PrivacyPolicyTargets() {
	static auto *targets = new LoadedDatabases();
	return *targets;
}

// Query-error redaction only makes sense for a hosted, multi-tenant server: a standalone DuckDB
// keeps its full diagnostics. Idempotent per database.
void InstallQueryErrorPrivacyIfHosted() {
#ifdef BOILSTREAM_HAS_QUERY_ERROR_PRIVACY
	if (!CatalogPlannerSlot().load(std::memory_order_acquire)) {
		return;
	}
	auto &targets = PrivacyPolicyTargets();
	std::lock_guard<std::mutex> guard(targets.mutex);
	for (auto it = targets.databases.begin(); it != targets.databases.end();) {
		if (auto db = it->lock()) {
			ExtensionCallbackManager::Get(*db).RegisterQueryErrorPrivacyCallback(BoilstreamPrivateQueryError,
			                                                                     BoilstreamPrivateErrorMessage);
			++it;
		} else {
			it = targets.databases.erase(it);
		}
	}
#endif
}


SessionRegistry &QuackSessionRegistry() {
	// Quack closes its final sessions from DuckDB's database-owner callback.
	// A process-global DuckDB may run that callback during static destruction,
	// after ordinary function-local statics in this extension were destroyed.
	// Keep this small registry alive until process reclamation so the callback's
	// mutex and map always share one valid lifetime.
	static auto *registry = new SessionRegistry();
	return *registry;
}

void BoilstreamQuackAuthnFunction(DataChunk &args, ExpressionState &, Vector &result) {
	auto verifier = JwtVerifierSlot().load(std::memory_order_acquire);
	TernaryExecutor::Execute<string_t, string_t, string_t, bool>(
		args.data[0], args.data[1], args.data[2], result, [verifier](string_t sid, string_t client_auth, string_t) {
			try {
				auto factory_v2 = ContextFactoryV2Slot().load(std::memory_order_acquire);
				auto factory = ContextFactorySlot().load(std::memory_order_acquire);
				auto create = factory_v2 ? factory_v2->create : factory ? factory->create : nullptr;
				auto destroy = factory_v2 ? factory_v2->destroy : factory ? factory->destroy : nullptr;
				if (!verifier || !create || !destroy ||
					(factory_v2 && (!factory_v2->requester_tenant || !factory_v2->max_sessions_per_tenant))) {
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
			    const auto authority = create(bundle.data());
			    if (!authority) {
				    return false;
			    }
			    // Capture the exact deallocator before publishing the owner.
			    // shared_ptr releases authority even if its allocation fails.
			    std::shared_ptr<const void> owned_authority(authority, destroy);
			    auto context = std::make_shared<SessionCtx>();
			    context->user_id = user_id;
			    context->capability_context = std::move(owned_authority);
				if (factory_v2) {
					const QuackRequesterTenant tenant(factory_v2->requester_tenant(authority));
					context->session_quota =
						QuackSessionRegistry().ReserveQuota(session_id, tenant, factory_v2->max_sessions_per_tenant);
					if (!context->session_quota)
						return false;
				}
				QuackSessionRegistry().Publish(session_id, std::move(context));
				return true;
			} catch (...) {
				return false;
			}
		});
}

// Authentication binds the immutable opaque context. This scalar only verifies that the
// same session exists; all operation authorization happens at the typed hook.
void BoilstreamQuackAuthzFunction(DataChunk &args, ExpressionState &, Vector &result) {
	BinaryExecutor::Execute<string_t, string_t, bool>(args.data[0], args.data[1], result, [](string_t sid, string_t) {
		try {
			return bool(GetQuackSessionCtx(std::string(sid.GetData(), sid.GetSize())));
		} catch (...) {
			return false;
		}
	});
}

void BoilstreamQuackDebugSessionCountFunction(DataChunk &args, ExpressionState &, Vector &result) {
	D_ASSERT(args.ColumnCount() == 0);
	auto &registry = QuackSessionRegistry();
	std::lock_guard<std::mutex> guard(registry.mutex);
	result.SetVectorType(VectorType::CONSTANT_VECTOR);
	ConstantVector::GetData<int32_t>(result)[0] = static_cast<int32_t>(registry.sessions.size());
}

} // namespace

std::shared_ptr<const SessionCtx> GetQuackSessionCtx(const std::string &session_id) {
	auto &registry = QuackSessionRegistry();
	std::lock_guard<std::mutex> guard(registry.mutex);
	auto found = registry.sessions.find(session_id);
	return found == registry.sessions.end() ? nullptr : found->second;
}

void RegisterQuackBridge(ExtensionLoader &loader) {
	{
		auto &targets = PrivacyPolicyTargets();
		std::lock_guard<std::mutex> guard(targets.mutex);
		targets.databases.emplace_back(loader.GetDatabaseInstance().shared_from_this());
	}
	loader.RegisterFunction(ScalarFunction("boilstream_quack_authn",
	                                       {LogicalType::VARCHAR, LogicalType::VARCHAR, LogicalType::VARCHAR},
	                                       LogicalType::BOOLEAN, BoilstreamQuackAuthnFunction));
	loader.RegisterFunction(ScalarFunction("boilstream_quack_authz", {LogicalType::VARCHAR, LogicalType::VARCHAR},
	                                       LogicalType::BOOLEAN, BoilstreamQuackAuthzFunction));
	loader.RegisterFunction(ScalarFunction("boilstream_quack_debug_session_count", {}, LogicalType::INTEGER,
	                                       BoilstreamQuackDebugSessionCountFunction));
	// Quack's admission hooks are installed only once a Rust host has registered a catalog planner
	// (InstallQuackAdmissionHooksIfHosted). Until then a statically linked Quack keeps its stock
	// behaviour, so standalone binaries and Quack's own tests are not failed closed by an absent host.
	QuackHookSetters().admission.store(reinterpret_cast<quack_set_catalog_admission_hooks_fn_t>(
	                                       boilstream_lookup_runtime_symbol("quack_set_catalog_admission_hooks")),
	                                   std::memory_order_release);
	QuackHookSetters().admission_v2.store(reinterpret_cast<quack_set_catalog_admission_hooks_v2_fn_t>(
        boilstream_lookup_runtime_symbol("quack_set_catalog_admission_hooks_v2")), std::memory_order_release);
	QuackHookSetters().admission_v3.store(reinterpret_cast<quack_set_catalog_admission_hooks_v3_fn_t>(
        boilstream_lookup_runtime_symbol("quack_set_catalog_admission_hooks_v3")), std::memory_order_release);
	QuackHookSetters().post_execute.store(reinterpret_cast<quack_set_post_execute_hook_fn_t>(
	                                          boilstream_lookup_runtime_symbol("quack_set_post_execute_hook")),
	                                      std::memory_order_release);
	InstallQuackAdmissionHooksIfHosted();
}

void InstallQuackAdmissionHooksIfHosted() {
	if (!CatalogPlannerSlot().load(std::memory_order_acquire)) {
		return; // no host yet
	}
	InstallQueryErrorPrivacyIfHosted();
	auto &setters = QuackHookSetters();
	if (!setters.installed.exchange(true)) {
		if (auto admission_setter = setters.admission_v3.load(std::memory_order_acquire)) {
            admission_setter(&boilstream_quack_catalog_plan, &boilstream_quack_catalog_authorize,
                             &boilstream_quack_catalog_session_close, &boilstream_quack_session_begin,
                             &boilstream_quack_session_finish, &boilstream_quack_session_requester_tenant);
        } else if (auto admission_setter = setters.admission_v2.load(std::memory_order_acquire)) {
            admission_setter(&boilstream_quack_catalog_plan, &boilstream_quack_catalog_authorize,
                             &boilstream_quack_catalog_session_close, &boilstream_quack_session_begin,
                             &boilstream_quack_session_finish);
        } else if (auto admission_setter = setters.admission.load(std::memory_order_acquire)) {
			admission_setter(&boilstream_quack_catalog_plan, &boilstream_quack_catalog_authorize,
			                 &boilstream_quack_catalog_session_close);
		}
		if (auto post_setter = setters.post_execute.load(std::memory_order_acquire)) {
			post_setter(&boilstream_quack_catalog_post_execute);
		}
	}
}

} // namespace duckdb

extern "C" void boilstream_quack_catalog_session_close(const char *session_id) {
 if (!session_id) return;
 try { duckdb::QuackSessionRegistry().Retire(session_id); } catch (...) {}
}

extern "C" uint32_t boilstream_quack_session_requester_tenant(const char *session_id) {
 if (!session_id || !*session_id) return 0;
 try {
  const auto context = duckdb::GetQuackSessionCtx(session_id);
  return context && context->session_quota ? context->session_quota->Tenant().Value() : 0;
 } catch (...) { return 0; }
}

extern "C" void *boilstream_quack_session_begin(const char *session_id) {
 if (!session_id || !*session_id) return nullptr;
 try { return duckdb::QuackSessionRegistry().Begin(session_id).release(); } catch (...) { return nullptr; }
}
extern "C" void boilstream_quack_session_finish(void *owner, uint32_t outcome) {
 if (!owner) return;
 try {
  duckdb::QuackSessionRegistry().Finish(
      std::unique_ptr<duckdb::SessionRegistry::Admission>(static_cast<duckdb::SessionRegistry::Admission *>(owner)),
      outcome == 1);
 } catch (...) {}
}

extern "C" int boilstream_quack_catalog_plan(const char *session_id, const char *declared_catalog_id,
                                             const char *sql_in, uint32_t *operation_out, char *catalog_id_out,
                                             size_t catalog_id_out_size, char *execution_catalog_alias_out,
                                             size_t execution_catalog_alias_out_size, char *read_catalog_alias_out,
                                             size_t read_catalog_alias_out_size, char *sql_out_buf, size_t sql_out_size,
                                             char *error_out_buf, size_t error_out_size) {
	ClearCatalogPlanDataOutputs(operation_out, catalog_id_out, catalog_id_out_size, execution_catalog_alias_out,
	                            execution_catalog_alias_out_size, read_catalog_alias_out, read_catalog_alias_out_size,
	                            sql_out_buf, sql_out_size);
	ClearBuffer(error_out_buf, error_out_size);
	try {
		if (!session_id || !declared_catalog_id || !sql_in || !operation_out || !catalog_id_out ||
		    catalog_id_out_size == 0 || !execution_catalog_alias_out || execution_catalog_alias_out_size == 0 ||
		    !read_catalog_alias_out || read_catalog_alias_out_size == 0 || !sql_out_buf || sql_out_size == 0 ||
		    !error_out_buf || error_out_size == 0) {
			WriteError(error_out_buf, error_out_size, "Catalog planner received invalid buffers");
			return -1;
		}
		auto planner = CatalogPlannerSlot().load(std::memory_order_acquire);
		if (!planner) {
			WriteError(error_out_buf, error_out_size, "Catalog planner is not registered");
			return -1;
		}
		auto session = duckdb::GetQuackSessionCtx(session_id);
		if (!session) {
			WriteError(error_out_buf, error_out_size, "Quack session capability context is missing");
			return -1;
		}
		const auto rc = planner(session->capability_context.get(), declared_catalog_id, sql_in, operation_out,
		                        catalog_id_out, catalog_id_out_size, execution_catalog_alias_out,
		                        execution_catalog_alias_out_size, read_catalog_alias_out, read_catalog_alias_out_size,
		                        sql_out_buf, sql_out_size, error_out_buf, error_out_size);
		if (rc == 0 || rc == 1) {
			return rc;
		}
		ClearCatalogPlanDataOutputs(operation_out, catalog_id_out, catalog_id_out_size, execution_catalog_alias_out,
		                            execution_catalog_alias_out_size, read_catalog_alias_out,
		                            read_catalog_alias_out_size, sql_out_buf, sql_out_size);
		if (error_out_buf[0] == '\0') {
			WriteError(error_out_buf, error_out_size,
			           rc < 0 ? "Catalog planner denied operation" : "Catalog planner returned invalid status");
		}
		return rc < 0 ? rc : -1;
	} catch (...) {
		ClearCatalogPlanDataOutputs(operation_out, catalog_id_out, catalog_id_out_size, execution_catalog_alias_out,
		                            execution_catalog_alias_out_size, read_catalog_alias_out,
		                            read_catalog_alias_out_size, sql_out_buf, sql_out_size);
		WriteError(error_out_buf, error_out_size, "Catalog planner bridge failed");
		return -1;
	}
}

extern "C" int boilstream_quack_catalog_authorize(const char *session_id, uint32_t operation, const char *catalog_id,
                                                  const char *execution_catalog_alias, const char *read_catalog_alias,
                                                  uint32_t *storage_owner_tenant_id_out, char *error_out_buf,
                                                  size_t error_out_size) {
	try {
		if (storage_owner_tenant_id_out) {
			*storage_owner_tenant_id_out = 0;
		}
		if (!session_id || !catalog_id || !execution_catalog_alias || !read_catalog_alias ||
		    !storage_owner_tenant_id_out || !error_out_buf || error_out_size == 0) {
			WriteError(error_out_buf, error_out_size, "Catalog authorizer received invalid buffers");
			return -1;
		}
		ClearBuffer(error_out_buf, error_out_size);
		auto authorizer = CatalogAuthorizerSlot().load(std::memory_order_acquire);
		if (!authorizer) {
			WriteError(error_out_buf, error_out_size, "Catalog authorizer is not registered");
			return -1;
		}
		auto session = duckdb::GetQuackSessionCtx(session_id);
		if (!session) {
			WriteError(error_out_buf, error_out_size, "Quack session capability context is missing");
			return -1;
		}
		const auto rc = authorizer(session->capability_context.get(), operation, catalog_id, execution_catalog_alias,
		                           read_catalog_alias, storage_owner_tenant_id_out, error_out_buf, error_out_size);
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
		if (!session) {
			WriteError(error_out_buf, error_out_size, "Quack session capability context is missing");
			return -1;
		}
		return hook(session->capability_context.get(), operation, catalog_id, error_out_buf, error_out_size);
	} catch (...) {
		WriteError(error_out_buf, error_out_size, "Post-execute bridge failed");
		return -1;
	}
}
