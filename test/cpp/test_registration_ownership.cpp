#include "duckdb.hpp"
#include "duckdb/main/config.hpp"
#include "boilstream_secret_storage.hpp"
#include <iostream>
#include <stdexcept>
#include <thread>
#include <atomic>
#include "duckdb/main/client_context_state.hpp"
#include "duckdb/main/tenant/active_tenant_registry.hpp"
#include "duckdb/main/tenant/tenant_context.hpp"
using namespace duckdb;
static void Require(bool value) {
	if (!value)
		throw std::runtime_error("assertion");
}
#ifdef BOILSTREAM_LEGACY_REGISTRATION
// Old API has no owner parameter. Keep the caller context in the adapter so
// exactly the same cross-connection assertions expose that missing boundary.
static void Store(RestApiSecretStorage &s, ClientContext &, const string &token) {
	s.StoreRegistrationState("https://same.invalid", token, "otpauth://synthetic");
}
static string Read(RestApiSecretStorage &s, ClientContext &) {
	return std::get<1>(s.GetRegistrationState());
}
static void Clear(RestApiSecretStorage &s, ClientContext &) {
	s.ClearRegistrationState();
}
#else
static void Store(RestApiSecretStorage &s, ClientContext &c, const string &token) {
	auto a = s.BeginRegistration(c, "https://same.invalid", "same@example.com");
	s.StoreRegistrationState(c, a.generation, token, "otpauth://synthetic");
	s.EndRegistrationOperation(c, a.generation);
}
static string Read(RestApiSecretStorage &s, ClientContext &c) {
	auto a = s.BeginMfaVerification(c);
	s.EndRegistrationOperation(c, a.generation);
	return a.session_token;
}
static void Clear(RestApiSecretStorage &s, ClientContext &c) {
	auto a = s.BeginMfaVerification(c);
	s.CompleteRegistration(c, a.generation);
}
#endif
struct Config : DBConfig {
	Config() {
		options.load_extensions = false;
		options.maximum_threads = 2;
	}
};
struct Fixture {
	Config cfg;
	DuckDB db {nullptr, &cfg};
	RestApiSecretStorage storage {*db.instance, ""};
	Connection a {db}, b {db};
};
template <class F>
static void Reject(F fn) {
	bool rejected = false;
	try {
		fn();
	} catch (const IOException &) {
		rejected = true;
	} catch (const InvalidInputException &) {
		rejected = true;
	}
	Require(rejected);
}
#ifndef BOILSTREAM_LEGACY_REGISTRATION
class BoilstreamSessionPublicationTestAccess {
public:
	static void Login(RestApiSecretStorage &s, ClientContext &ctx, const string &identity) {
		auto old = s.GetSessionForConnection(ctx.GetConnectionId());
		auto state = make_shared_ptr<BoilstreamConnectionState>("https://same.invalid");
		state->bootstrap_token_hash = identity;
		state->access_token = "synthetic-token";
		state->session_key.assign(32, 7);
		state->token_expires_at = std::chrono::system_clock::now() + std::chrono::hours(1);
		s.PublishSession(ctx, state, old, old ? old->authentication_generation.load() : 0, false);
	}
};
#endif
int main() {
	int failures = 0;
	auto test = [&](const char *name, auto fn) {
		try {
			fn();
			std::cout << "CASE " << name << " PASS\n";
		} catch (...) {
			++failures;
			std::cout << "CASE " << name << " FAIL\n";
		}
	};
	test("owner_can_read_pending_registration", [] {
		Fixture f;
		Store(f.storage, *f.a.context, "synthetic-a");
		Require(Read(f.storage, *f.a.context) == "synthetic-a");
	});
	test("other_connection_cannot_read_registration", [] {
		Fixture f;
		Store(f.storage, *f.a.context, "synthetic-a");
		bool rejected = false;
		try {
			Read(f.storage, *f.b.context);
		} catch (const IOException &) {
			rejected = true;
		}
		Require(rejected);
	});
	test("other_connection_cannot_replace_registration", [] {
		Fixture f;
		Store(f.storage, *f.a.context, "synthetic-a");
		Store(f.storage, *f.b.context, "synthetic-b");
		Require(Read(f.storage, *f.a.context) == "synthetic-a" && Read(f.storage, *f.b.context) == "synthetic-b");
	});
	test("other_connection_cannot_clear_registration", [] {
		Fixture f;
		Store(f.storage, *f.a.context, "synthetic-a");
		try {
			Clear(f.storage, *f.b.context);
		} catch (const IOException &) {
		}
		Require(Read(f.storage, *f.a.context) == "synthetic-a");
	});

#ifndef BOILSTREAM_LEGACY_REGISTRATION
	test("same_identity_reuses_only_its_own_pending_secret", [] {
		Fixture f;
		Store(f.storage, *f.a.context, "synthetic-a");
		auto cached = f.storage.BeginRegistration(*f.a.context, "https://same.invalid", "same@example.com");
		Require(cached.session_token == "synthetic-a" && cached.totp_uri == "otpauth://synthetic");
		f.storage.EndRegistrationOperation(*f.a.context, cached.generation);
	});
	test("new_email_discards_previous_credentials", [] {
		Fixture f;
		Store(f.storage, *f.a.context, "synthetic-a");
		auto next = f.storage.BeginRegistration(*f.a.context, "https://same.invalid", "next@example.com");
		Require(next.session_token.empty() && next.totp_uri.empty());
		f.storage.EndRegistrationOperation(*f.a.context, next.generation);
		Reject([&] { Read(f.storage, *f.a.context); });
	});
	test("new_authority_discards_previous_credentials", [] {
		Fixture f;
		Store(f.storage, *f.a.context, "synthetic-a");
		auto next = f.storage.BeginRegistration(*f.a.context, "https://other.invalid", "same@example.com");
		Require(next.session_token.empty());
		f.storage.EndRegistrationOperation(*f.a.context, next.generation);
		Reject([&] { Read(f.storage, *f.a.context); });
	});
	test("stale_publication_does_not_replace_successor", [] {
		Fixture f;
		auto old = f.storage.BeginRegistration(*f.a.context, "https://same.invalid", "first@example.com");
		f.storage.EndRegistrationOperation(*f.a.context, old.generation);
		auto next = f.storage.BeginRegistration(*f.a.context, "https://same.invalid", "next@example.com");
		Require(old.generation != next.generation);
		Reject([&] { f.storage.StoreRegistrationState(*f.a.context, old.generation, "old", "uri"); });
		f.storage.StoreRegistrationState(*f.a.context, next.generation, "next", "uri");
		f.storage.EndRegistrationOperation(*f.a.context, next.generation);
		Require(Read(f.storage, *f.a.context) == "next");
	});
	test("foreign_operation_id_cannot_publish", [] {
		Fixture f;
		auto a = f.storage.BeginRegistration(*f.a.context, "https://same.invalid", "same@example.com");
		auto b = f.storage.BeginRegistration(*f.b.context, "https://same.invalid", "same@example.com");
		Require(a.generation != b.generation);
		Reject([&] { f.storage.StoreRegistrationState(*f.b.context, a.generation, "foreign", "uri"); });
		f.storage.StoreRegistrationState(*f.b.context, b.generation, "owned", "uri");
		f.storage.EndRegistrationOperation(*f.b.context, b.generation);
		Require(Read(f.storage, *f.b.context) == "owned");
	});
	test("late_cleanup_cannot_unlock_current_verification", [] {
		Fixture f;
		Store(f.storage, *f.a.context, "synthetic-a");
		auto old = f.storage.BeginMfaVerification(*f.a.context);
		f.storage.EndRegistrationOperation(*f.a.context, old.generation);
		auto current = f.storage.BeginMfaVerification(*f.a.context);
		f.storage.EndRegistrationOperation(*f.a.context, old.generation);
		Reject([&] { f.storage.BeginMfaVerification(*f.a.context); });
		Reject([&] { f.storage.CompleteRegistration(*f.a.context, old.generation); });
		f.storage.EndRegistrationOperation(*f.a.context, current.generation);
		Require(Read(f.storage, *f.a.context) == "synthetic-a");
	});
	test("successful_mfa_consumes_registration", [] {
		Fixture f;
		Store(f.storage, *f.a.context, "synthetic-a");
		Clear(f.storage, *f.a.context);
		Reject([&] { Read(f.storage, *f.a.context); });
	});
	test("registration_operation_cannot_complete_mfa", [] {
		Fixture f;
		Store(f.storage, *f.a.context, "synthetic-a");
		auto cached = f.storage.BeginRegistration(*f.a.context, "https://same.invalid", "same@example.com");
		Reject([&] { f.storage.CompleteRegistration(*f.a.context, cached.generation); });
		f.storage.EndRegistrationOperation(*f.a.context, cached.generation);
		Require(Read(f.storage, *f.a.context) == "synthetic-a");
	});
	test("tenant_change_retires_old_registration_permanently", [] {
		Fixture f;
		TenantContext a, b;
		a.SetTenantId("42");
		b.SetTenantId("43");
		{
			ActiveTenantRegistry::Guard guard(*f.db.instance, &a);
			Store(f.storage, *f.a.context, "tenant-a");
		}
		{
			ActiveTenantRegistry::Guard guard(*f.db.instance, &b);
			Reject([&] { Read(f.storage, *f.a.context); });
		}
		{
			ActiveTenantRegistry::Guard guard(*f.db.instance, &a);
			Reject([&] { Read(f.storage, *f.a.context); });
		}
	});
	test("worker_reuse_preserves_distinct_connection_owners", [] {
		Fixture f;
		TenantContext a, b;
		a.SetTenantId("42");
		b.SetTenantId("43");
		{
			ActiveTenantRegistry::Guard guard(*f.db.instance, &a);
			Store(f.storage, *f.a.context, "tenant-a");
		}
		{
			ActiveTenantRegistry::Guard guard(*f.db.instance, &b);
			Store(f.storage, *f.b.context, "tenant-b");
		}
		{
			ActiveTenantRegistry::Guard guard(*f.db.instance, &a);
			Require(Read(f.storage, *f.a.context) == "tenant-a");
		}
		{
			ActiveTenantRegistry::Guard guard(*f.db.instance, &b);
			Require(Read(f.storage, *f.b.context) == "tenant-b");
		}
	});
	test("cancellation_invalidates_pending_publication", [] {
		Fixture f;
		auto pending = f.storage.BeginRegistration(*f.a.context, "https://same.invalid", "same@example.com");
		f.a.context->Interrupt();
		Reject([&] { f.storage.StoreRegistrationState(*f.a.context, pending.generation, "token", "uri"); });
		f.storage.EndRegistrationOperation(*f.a.context, pending.generation);
		f.a.context->ClearInterrupt();
		Reject([&] { Read(f.storage, *f.a.context); });
		Store(f.storage, *f.a.context, "fresh");
		Require(Read(f.storage, *f.a.context) == "fresh");
	});
	test("cancelled_verification_cannot_resume_old_cookie", [] {
		Fixture f;
		Store(f.storage, *f.a.context, "synthetic-a");
		auto pending = f.storage.BeginMfaVerification(*f.a.context);
		f.a.context->Interrupt();
		f.storage.EndRegistrationOperation(*f.a.context, pending.generation);
		f.a.context->ClearInterrupt();
		Reject([&] { Read(f.storage, *f.a.context); });
	});
	test("connection_destruction_releases_registration_owner", [] {
		Fixture f;
		weak_ptr<ClientContextState> owner;
		{
			Connection temporary(f.db);
			Store(f.storage, *temporary.context, "temporary");
			auto state = temporary.context->registered_state->Get<ClientContextState>("boilstream_registration");
			Require(bool(state));
			owner = state;
		}
		Require(owner.expired());
		Connection fresh(f.db);
		Reject([&] { Read(f.storage, *fresh.context); });
	});
	test("foreign_database_context_is_rejected", [] {
		Fixture f, g;
		Reject([&] { Store(f.storage, *g.a.context, "foreign"); });
		Store(g.storage, *g.a.context, "owned");
		Require(Read(g.storage, *g.a.context) == "owned");
	});
	test("credential_bounds_and_control_bytes_rejected", [] {
		Fixture f;
		for (const auto &invalid : vector<string> {"", string(4097, 'x'), string("a\0b", 3), "a\nb"}) {
			auto op = f.storage.BeginRegistration(*f.a.context, "https://same.invalid", "same@example.com");
			Reject([&] { f.storage.StoreRegistrationState(*f.a.context, op.generation, invalid, "uri"); });
			Reject([&] { f.storage.StoreRegistrationState(*f.a.context, op.generation, "token", invalid); });
			f.storage.EndRegistrationOperation(*f.a.context, op.generation);
		}
		auto op = f.storage.BeginRegistration(*f.a.context, "https://same.invalid", "same@example.com");
		f.storage.StoreRegistrationState(*f.a.context, op.generation, string(4096, 'x'), string(4096, 'u'));
		f.storage.EndRegistrationOperation(*f.a.context, op.generation);
		Require(Read(f.storage, *f.a.context).size() == 4096);
	});
	test("identity_bounds_preserve_existing_owner", [] {
		Fixture f;
		Store(f.storage, *f.a.context, "owned");
		for (const auto &email : vector<string> {"", string(321, 'x'), string("a\0b", 3), "a\nb"})
			Reject([&] { f.storage.BeginRegistration(*f.a.context, "https://same.invalid", email); });
		Reject([&] { f.storage.BeginRegistration(*f.a.context, string(4097, 'x'), "same@example.com"); });
		Require(Read(f.storage, *f.a.context) == "owned");
	});
	test("concurrent_connections_remain_independent", [] {
		Fixture f;
		std::atomic<bool> correct {true};
		auto run = [&](Connection &c, const string &token) {
			try {
				for (int i = 0; i < 30; ++i) {
					Store(f.storage, *c.context, token);
					Require(Read(f.storage, *c.context) == token);
					Clear(f.storage, *c.context);
				}
			} catch (...) {
				correct = false;
			}
		};
		std::thread a(run, std::ref(f.a), "worker-a"), b(run, std::ref(f.b), "worker-b");
		a.join();
		b.join();
		Require(correct);
	});
	test("same_connection_allows_one_verification_lease", [] {
		Fixture f;
		Store(f.storage, *f.a.context, "owned");
		std::atomic<int> entered {0}, accepted {0};
		std::atomic<bool> release {false};
		auto run = [&] {
			try {
				auto op = f.storage.BeginMfaVerification(*f.a.context);
				++accepted;
				++entered;
				while (!release.load())
					std::this_thread::yield();
				f.storage.EndRegistrationOperation(*f.a.context, op.generation);
			} catch (const IOException &) {
				++entered;
			}
		};
		std::thread a(run), b(run);
		while (entered.load() != 2)
			std::this_thread::yield();
		const auto admitted = accepted.load();
		release = true;
		a.join();
		b.join();
		Require(admitted == 1);
		Require(Read(f.storage, *f.a.context) == "owned");
	});

	test("query_begin_retires_previous_tenant_enrollment", [] {
		Fixture f;
		TenantContext a, b;
		a.SetTenantId("42");
		b.SetTenantId("43");
		{
			ActiveTenantRegistry::Guard guard(*f.db.instance, &a);
			Store(f.storage, *f.a.context, "tenant-a");
		}
		{
			ActiveTenantRegistry::Guard guard(*f.db.instance, &b);
			auto r = f.a.Query("SELECT 1");
			Require(r && !r->HasError());
		}
		{
			ActiveTenantRegistry::Guard guard(*f.db.instance, &a);
			Reject([&] { Read(f.storage, *f.a.context); });
		}
	});
	test("oversized_tenant_rejected_and_old_state_retired", [] {
		Fixture f;
		Store(f.storage, *f.a.context, "standalone");
		TenantContext large;
		// Fault-inject the public worker context field; the SQL setter already rejects this size.
		large.tenant_id = string(4097, '9');
		{
			ActiveTenantRegistry::Guard guard(*f.db.instance, &large);
			Reject([&] { f.storage.BeginRegistration(*f.a.context, "https://same.invalid", "same@example.com"); });
		}
		Reject([&] { Read(f.storage, *f.a.context); });
	});

	test("reauthentication_retires_previous_account_enrollment", [] {
		Fixture f;
		BoilstreamSessionPublicationTestAccess::Login(f.storage, *f.a.context, "first");
		Store(f.storage, *f.a.context, "enrollment");
		BoilstreamSessionPublicationTestAccess::Login(f.storage, *f.a.context, "second");
		Reject([&] { Read(f.storage, *f.a.context); });
	});
	test("logout_retires_enrollment_even_with_same_session_object", [] {
		Fixture f;
		BoilstreamSessionPublicationTestAccess::Login(f.storage, *f.a.context, "first");
		Store(f.storage, *f.a.context, "enrollment");
		f.storage.ClearSession(*f.a.context);
		Reject([&] { Read(f.storage, *f.a.context); });
	});
	test("first_login_retires_unauthenticated_enrollment", [] {
		Fixture f;
		Store(f.storage, *f.a.context, "enrollment");
		BoilstreamSessionPublicationTestAccess::Login(f.storage, *f.a.context, "first");
		Reject([&] { Read(f.storage, *f.a.context); });
	});
#endif
	return failures ? 1 : 0;
}
