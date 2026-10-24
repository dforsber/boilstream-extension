// Actual result-table execution plus storage lifecycle and ownership boundaries.
#include "../../src/boilstream_extension.cpp"
#include "duckdb/main/config.hpp"
#include "duckdb/parser/parsed_data/create_scalar_function_info.hpp"
#include "duckdb/execution/expression_executor_state.hpp"
#include "duckdb/main/client_context_state.hpp"
#include "duckdb/main/tenant/active_tenant_registry.hpp"
#include "duckdb/main/tenant/tenant_context.hpp"
#include <iostream>
#include <thread>
#include <atomic>
using namespace duckdb;
static void Require(bool value) {
	if (!value)
		throw std::runtime_error("assertion");
}
template <class F>
static void Reject(F f) {
	bool rejected = false;
	try {
		f();
	} catch (const IOException &) {
		rejected = true;
	} catch (const InvalidInputException &) {
		rejected = true;
	}
	Require(rejected);
}
static unique_ptr<BoilstreamRegistrationOutput> Output(const string &value = "synthetic-secret") {
	auto out = make_uniq<BoilstreamRegistrationOutput>();
	out->rows.push_back({value, false});
	return out;
}
class BoilstreamSessionPublicationTestAccess {
public:
	static shared_ptr<BoilstreamConnectionState> Login(RestApiSecretStorage &s, ClientContext &ctx) {
		auto old = s.GetSessionForConnection(ctx.GetConnectionId());
		auto next = make_shared_ptr<BoilstreamConnectionState>();
		next->session_key.assign(64, 7);
		next->access_token = "synthetic-token";
		next->token_expires_at = std::chrono::system_clock::now() + std::chrono::hours(1);
		s.PublishSession(ctx, next, old, old ? old->authentication_generation.load() : 0, false);
		return next;
	}
};
struct Config : DBConfig {
	Config() {
		options.load_extensions = false;
		options.maximum_threads = 2;
	}
};
struct Fixture {
	Config cfg;
	DuckDB db {nullptr, &cfg};
	Connection a {db}, b {db};
	RestApiSecretStorage *storage;
	Fixture() {
		SecretManager::Get(*db.instance).SetEnablePersistentSecrets(false);
		Require(ExtensionHelper::LoadExtension(db, "core_functions") == ExtensionLoadResult::LOADED_EXTENSION);
		db.LoadStaticExtension<BoilstreamExtension>();
		storage = GetStorageFromContext(*a.context);
		Require(storage);
	}
	BoilstreamRegistrationSnapshot Begin(Connection &c) {
		auto state = storage->BeginRegistration(*c.context, "https://same.invalid", "same@example.com");
		if (state.totp_uri.empty())
			storage->StoreRegistrationState(*c.context, state.generation, "synthetic-cookie",
			                                "otpauth://totp/synthetic?secret=ABCD");
		return state;
	}
	uint64_t Publish(Connection &c, const string &value = "synthetic-secret") {
		auto op = Begin(c);
		auto id = storage->PublishRegistrationOutput(*c.context, op.generation, Output(value));
		storage->EndRegistrationOperation(*c.context, op.generation);
		return id;
	}
	string Sql(uint64_t id) {
		return "SELECT value FROM boilstream_auth_result(" + std::to_string(id) + "::UBIGINT) ORDER BY ordinal";
	}
	string Read(Connection &c, uint64_t id) {
		auto r = c.Query(Sql(id));
		Require(r && !r->HasError() && r->RowCount() == 1);
		return r->Collection().GetValue(0, 0).ToString();
	}
};
int main() {
	int failed = 0;
	auto test = [&](const char *name, auto fn) {
		try {
			fn();
			std::cout << "CASE " << name << " PASS" << std::endl;
		} catch (...) {
			++failed;
			std::cout << "CASE " << name << " FAIL" << std::endl;
		}
	};
	test("result_sql_returns_exact_owned_value", [] {
		Fixture f;
		auto id = f.Publish(f.a);
		Require(f.Read(f.a, id) == "synthetic-secret");
	});
	test("result_can_be_consumed_only_once", [] {
		Fixture f;
		auto id = f.Publish(f.a);
		Require(f.Read(f.a, id) == "synthetic-secret");
		Require(f.a.Query(f.Sql(id))->HasError());
	});
	test("foreign_connection_cannot_consume_or_clear_owner", [] {
		Fixture f;
		auto id = f.Publish(f.a);
		Require(f.b.Query(f.Sql(id))->HasError());
		Require(f.Read(f.a, id) == "synthetic-secret");
	});
	test("equal_named_results_remain_connection_owned", [] {
		Fixture f;
		auto a = f.Publish(f.a, "owner-a"), b = f.Publish(f.b, "owner-b");
		Require(a != b);
		Require(f.Read(f.a, a) == "owner-a" && f.Read(f.b, b) == "owner-b");
	});
	test("stale_query_cannot_consume_or_clear_replacement", [] {
		Fixture f;
		auto old = f.Publish(f.a, "old"), next = f.Publish(f.a, "next");
		Require(f.a.Query(f.Sql(old))->HasError());
		Require(f.Read(f.a, next) == "next");
	});
	test("preparation_does_not_consume_or_embed_payload", [] {
		Fixture f;
		auto id = f.Publish(f.a);
		auto prepared = f.a.Prepare(f.Sql(id));
		Require(prepared && !prepared->HasError());
		Require(prepared->GetQuery().find("synthetic-secret") == string::npos);
		auto r = prepared->Execute();
		Require(!r->HasError());
		auto chunk = r->Fetch();
		Require(chunk && chunk->size() == 1 && chunk->GetValue(0, 0).ToString() == "synthetic-secret");
		auto end = r->Fetch();
		Require(!end || end->size() == 0);
		Require(prepared->Execute()->HasError());
	});
	test("explain_does_not_consume_or_embed_payload", [] {
		Fixture f;
		auto id = f.Publish(f.a);
		auto plan = f.a.Query("EXPLAIN " + f.Sql(id));
		Require(!plan->HasError() && plan->ToString().find("synthetic-secret") == string::npos);
		Require(f.Read(f.a, id) == "synthetic-secret");
	});
	test("prepared_old_id_cannot_read_new_result", [] {
		Fixture f;
		auto old = f.Publish(f.a, "old");
		auto prepared = f.a.Prepare(f.Sql(old));
		Require(!prepared->HasError());
		auto next = f.Publish(f.a, "next");
		Require(prepared->Execute()->HasError());
		Require(f.Read(f.a, next) == "next");
	});
	test("result_is_unavailable_while_operation_is_busy", [] {
		Fixture f;
		auto op = f.Begin(f.a);
		auto id = f.storage->PublishRegistrationOutput(*f.a.context, op.generation, Output());
		Reject([&] { f.storage->TakeRegistrationOutput(*f.a.context, id); });
		f.storage->EndRegistrationOperation(*f.a.context, op.generation);
		Require(f.Read(f.a, id) == "synthetic-secret");
	});
	test("foreign_operation_cannot_publish_result", [] {
		Fixture f;
		auto a = f.Begin(f.a), b = f.Begin(f.b);
		Reject([&] { f.storage->PublishRegistrationOutput(*f.b.context, a.generation, Output()); });
		f.storage->EndRegistrationOperation(*f.b.context, b.generation);
		f.storage->EndRegistrationOperation(*f.a.context, a.generation);
	});
	test("completion_result_consumes_enrollment_not_payload", [] {
		Fixture f;
		f.Publish(f.a);
		auto op = f.storage->BeginMfaVerification(*f.a.context);
		auto id = f.storage->CompleteRegistration(*f.a.context, op.generation, Output("recovery"));
		Reject([&] { f.storage->BeginMfaVerification(*f.a.context); });
		Require(f.Read(f.a, id) == "recovery");
	});
	test("registration_cannot_publish_verification_result", [] {
		Fixture f;
		auto op = f.Begin(f.a);
		Reject([&] { f.storage->CompleteRegistration(*f.a.context, op.generation, Output()); });
		f.storage->EndRegistrationOperation(*f.a.context, op.generation);
	});
	test("verification_cannot_publish_registration_result", [] {
		Fixture f;
		f.Publish(f.a);
		auto op = f.storage->BeginMfaVerification(*f.a.context);
		Reject([&] { f.storage->PublishRegistrationOutput(*f.a.context, op.generation, Output()); });
		f.storage->EndRegistrationOperation(*f.a.context, op.generation);
	});
	test("result_bounds_reject_empty_oversized_and_control_bytes", [] {
		Fixture f;
		auto op = f.Begin(f.a);
		for (auto value :
		     vector<string> {"", string(8193, 'a'), "line\nbreak", string("nul\0tail", 8), string(1, char(127))})
			Reject([&] { f.storage->PublishRegistrationOutput(*f.a.context, op.generation, Output(value)); });
		Reject([&] {
			f.storage->PublishRegistrationOutput(*f.a.context, op.generation,
			                                     make_uniq<BoilstreamRegistrationOutput>());
		});
		auto out = Output();
		out->rows.resize(129);
		Reject([&] { f.storage->PublishRegistrationOutput(*f.a.context, op.generation, std::move(out)); });
		Reject([&] { f.storage->PublishRegistrationOutput(*f.a.context, op.generation, nullptr); });
		f.storage->EndRegistrationOperation(*f.a.context, op.generation);
	});
	test("result_boundary_accepts_128_rows_and_8192_bytes", [] {
		Fixture f;
		auto op = f.Begin(f.a);
		auto out = make_uniq<BoilstreamRegistrationOutput>();
		for (int i = 0; i < 128; ++i)
			out->rows.push_back({string(8192, char('a' + i % 26)), false});
		auto id = f.storage->PublishRegistrationOutput(*f.a.context, op.generation, std::move(out));
		f.storage->EndRegistrationOperation(*f.a.context, op.generation);
		auto r = f.a.Query(f.Sql(id));
		Require(!r->HasError() && r->RowCount() == 128);
		for (idx_t i = 0; i < 128; ++i)
			Require(r->Collection().GetValue(0, i).ToString() == string(8192, char('a' + i % 26)));
	});
	test("interruption_retires_pending_result", [] {
		Fixture f;
		auto id = f.Publish(f.a);
		f.a.context->Interrupt();
		Reject([&] { f.storage->TakeRegistrationOutput(*f.a.context, id); });
		Require(!f.a.Query("SELECT 1")->HasError());
		Require(f.a.Query(f.Sql(id))->HasError());
	});
	test("tenant_change_retires_pending_result_permanently", [] {
		Fixture f;
		TenantContext a, b;
		a.SetTenantId("42");
		b.SetTenantId("43");
		uint64_t id;
		{
			ActiveTenantRegistry::Guard g(*f.db.instance, &a);
			id = f.Publish(f.a);
		}
		{
			ActiveTenantRegistry::Guard g(*f.db.instance, &b);
			Reject([&] { f.storage->TakeRegistrationOutput(*f.a.context, id); });
		}
		{
			ActiveTenantRegistry::Guard g(*f.db.instance, &a);
			Reject([&] { f.storage->TakeRegistrationOutput(*f.a.context, id); });
		}
	});
	test("first_login_retires_unauthenticated_output", [] {
		Fixture f;
		auto id = f.Publish(f.a);
		BoilstreamSessionPublicationTestAccess::Login(*f.storage, *f.a.context);
		Reject([&] { f.storage->TakeRegistrationOutput(*f.a.context, id); });
	});
	test("reauthentication_retires_previous_account_output", [] {
		Fixture f;
		BoilstreamSessionPublicationTestAccess::Login(*f.storage, *f.a.context);
		auto id = f.Publish(f.a);
		BoilstreamSessionPublicationTestAccess::Login(*f.storage, *f.a.context);
		Reject([&] { f.storage->TakeRegistrationOutput(*f.a.context, id); });
	});
	test("logout_generation_retires_output", [] {
		Fixture f;
		auto auth = BoilstreamSessionPublicationTestAccess::Login(*f.storage, *f.a.context);
		auto id = f.Publish(f.a);
		auth->ClearSession();
		Reject([&] { f.storage->TakeRegistrationOutput(*f.a.context, id); });
	});
	test("foreign_database_cannot_take_result", [] {
		Fixture f;
		Config cfg;
		DuckDB db(nullptr, &cfg);
		Connection c(db);
		auto id = f.Publish(f.a);
		Reject([&] { f.storage->TakeRegistrationOutput(*c.context, id); });
		Require(f.Read(f.a, id) == "synthetic-secret");
	});
	test("closed_connection_result_is_not_inherited", [] {
		Fixture f;
		uint64_t id;
		{
			Connection short_lived(f.db);
			id = f.Publish(short_lived);
		}
		Connection next(f.db);
		Require(next.Query(f.Sql(id))->HasError());
	});
	test("competing_readers_have_exactly_one_winner", [] {
		Fixture f;
		auto id = f.Publish(f.a);
		std::atomic<int> successes {0}, rejections {0}, ready {0};
		std::atomic<bool> start {false};
		auto read = [&] {
			++ready;
			while (!start.load())
				std::this_thread::yield();
			try {
				auto out = f.storage->TakeRegistrationOutput(*f.a.context, id);
				if (out->rows.size() == 1 && out->rows[0].value == "synthetic-secret")
					++successes;
			} catch (const IOException &) {
				++rejections;
			}
		};
		std::thread a(read), b(read);
		while (ready.load() != 2)
			std::this_thread::yield();
		start = true;
		a.join();
		b.join();
		Require(successes == 1 && rejections == 1);
	});
	test("parallel_connections_preserve_output_values", [] {
		Fixture f;
		std::atomic<bool> ok {true};
		auto work = [&](Connection &c, const string &value) {
			try {
				auto id = f.Publish(c, value);
				if (f.Read(c, id) != value)
					ok = false;
			} catch (...) {
				ok = false;
			}
		};
		std::thread a([&] { work(f.a, "a"); }), b([&] { work(f.b, "b"); });
		a.join();
		b.join();
		Require(ok);
	});
	test("runtime_values_cannot_become_sql_syntax", [] {
		Fixture f;
		Require(
		    !f.a.Query("CREATE TABLE protected_data(i INTEGER); INSERT INTO protected_data VALUES (42)")->HasError());
		const string value = "'); DROP TABLE protected_data; SELECT '";
		auto id = f.Publish(f.a, value);
		Require(f.Read(f.a, id) == value);
		auto r = f.a.Query("SELECT i FROM protected_data");
		Require(!r->HasError() && r->RowCount() == 1 && r->Collection().GetValue(0, 0).GetValue<int32_t>() == 42);
	});
	test("execution_error_cannot_restore_consumed_payload", [] {
		Fixture f;
		auto id = f.Publish(f.a, "not-a-number");
		auto r = f.a.Query("SELECT value::INTEGER FROM boilstream_auth_result(" + std::to_string(id) + "::UBIGINT)");
		Require(r->HasError());
		Require(f.a.Query(f.Sql(id))->HasError());
	});

	test("foreign_result_id_preserves_both_connections_pending_values", [] {
		Fixture f;
		auto a = f.Publish(f.a, "owner-a"), b = f.Publish(f.b, "owner-b");
		Require(f.b.Query(f.Sql(a))->HasError());
		Require(f.Read(f.b, b) == "owner-b" && f.Read(f.a, a) == "owner-a");
	});
	test("cancellation_end_hook_retires_pending_result", [] {
		Fixture f;
		auto id = f.Publish(f.a);
		ErrorData error(ExceptionType::INTERRUPT, "synthetic cancellation");
		for (const auto &state : f.a.context->registered_state->States())
			state->QueryEnd(*f.a.context, &error);
		Require(f.a.Query(f.Sql(id))->HasError());
	});
	test("unrelated_success_preserves_pending_result", [] {
		Fixture f;
		auto id = f.Publish(f.a);
		Require(!f.a.Query("SELECT 42")->HasError());
		Require(f.Read(f.a, id) == "synthetic-secret");
	});
	test("invalid_sql_result_ids_preserve_pending_value", [] {
		Fixture f;
		auto id = f.Publish(f.a);
		for (const string input : {"NULL::UBIGINT", "0::UBIGINT", "18446744073709551615::UBIGINT", "-1::UBIGINT"})
			Require(f.a.Query("SELECT * FROM boilstream_auth_result(" + input + ")")->HasError());
		Require(f.Read(f.a, id) == "synthetic-secret");
	});
	test("actual_query_cancellation_retires_pending_result", [] {
		Fixture f;
		CreateScalarFunctionInfo cancel(ScalarFunction("cancel_auth_result", {LogicalType::BIGINT}, LogicalType::BIGINT,
		                                               [](DataChunk &, ExpressionState &state, Vector &) {
			                                               state.GetContext().Interrupt();
			                                               throw InterruptException();
		                                               }));
		f.a.context->RunFunctionInTransaction(
		    [&]() { Catalog::GetSystemCatalog(*f.a.context).CreateFunction(*f.a.context, cancel); });
		auto id = f.Publish(f.a);
		auto result = f.a.Query("SELECT cancel_auth_result(i) FROM range(1) t(i)");
		Require(result->HasError() && result->GetErrorObject().Type() == ExceptionType::INTERRUPT);
		Require(f.a.Query(f.Sql(id))->HasError());
		Require(!f.a.Query("SELECT 42")->HasError());
	});
	return failed ? 1 : 0;
}
