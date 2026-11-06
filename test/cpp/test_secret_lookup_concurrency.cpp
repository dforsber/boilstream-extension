// Actual authenticated HTTP + native storage path, using synthetic credentials.
// The companion Python authority independently signs responses and gates request 1.
#include "duckdb.hpp"
#include "duckdb/main/config.hpp"
#include "duckdb/main/extension_helper.hpp"
#include "boilstream_secret_storage.hpp"
#include "secret_response_fixture.hpp"
#include <future>
#include <iostream>
#include <thread>
using namespace duckdb;

class BoilstreamSessionPublicationTestAccess {
public:
	static string Encode(RestApiSecretStorage &storage) {
		KeyValueSecret secret({"test://shared/"}, "owned_test", "config", "owned");
		secret.secret_map["key"] = Value("synthetic-value");
		return storage.SerializeSecret(secret); // Unknown expiry remains null.
	}
	static void CacheKnownExpiry(RestApiSecretStorage &storage, BoilstreamConnectionState &state) {
		storage.PublishSecretList("[" + WithFixtureExpiry(Encode(storage)) + "]", state,
		                          state.secret_cache->Revision());
	}
	static shared_ptr<BoilstreamConnectionState> Publish(RestApiSecretStorage &storage, ClientContext &context,
	                                                     const string &endpoint) {
		auto state = make_shared_ptr<BoilstreamConnectionState>(endpoint);
		state->session_key.assign(64, 7);
		state->access_token = string(64, 'a');
		state->region = "synthetic-region";
		state->bootstrap_token_hash = "synthetic-concurrent-lookup";
		state->token_expires_at = std::chrono::system_clock::now() + std::chrono::hours(1);
		auto previous = storage.GetSessionForConnection(context.GetConnectionId());
		storage.PublishSession(context, state, previous, previous ? previous->authentication_generation.load() : 0,
		                       false);
		return state;
	}
};
struct Config : DBConfig {
	Config() {
		options.load_extensions = false;
		options.maximum_threads = 2;
	}
};
struct JoinThread {
	std::thread &thread;
	~JoinThread() {
		if (thread.joinable())
			thread.join();
	}
};
static bool LocalGuardRemainsNonblocking() {
	int owner = 0;
	BoilstreamLocalSecretHostV2 host {};
	host.version = 2;
	host.size = sizeof(host);
	host.owner = &owner;
	host.expires_at_us = std::chrono::duration_cast<std::chrono::microseconds>(
	                         (std::chrono::system_clock::now() + std::chrono::hours(1)).time_since_epoch())
	                         .count();
	host.retain = [](const void *) {
	};
	host.release = [](const void *) {
	};
	host.release_reply = [](void *) {
	};
	host.request = [](const void *, void *, const uint8_t *, size_t, BoilstreamLocalSecretReplyV1 *) -> uint8_t {
		return 0;
	};
	auto provider = make_shared_ptr<BoilstreamLocalSecretProvider>(host);
	BoilstreamConnectionState state(provider);
	bool entered = false, refused = false;
	std::future<bool> result;
	std::thread worker;
	{
		BoilstreamConnectionState::SecretLookupGuard held(state);
		entered = held.Acquired();
		std::packaged_task<bool()> attempt([&] {
			BoilstreamConnectionState::SecretLookupGuard nested(state);
			return nested.Acquired();
		});
		result = attempt.get_future();
		worker = std::thread(std::move(attempt));
		if (result.wait_for(std::chrono::seconds(1)) == std::future_status::ready)
			refused = !result.get();
	} // Release even if a mistaken blocking implementation stalled the worker.
	worker.join();
	return entered && refused;
}
int main(int argc, char **argv) {
	if (argc != 3)
		return 2;
	try {
		const string mode = argv[2];
		const bool normal = mode == "normal";
		if (!normal && mode != "expired" && mode != "replaced" && mode != "generation" && mode != "cancelled" &&
		    mode != "cancelled_cached")
			throw std::runtime_error("invalid fixture mode");
		Config config;
		DuckDB db(nullptr, &config);
		Connection connection(db);
		SecretManager::Get(*db.instance).SetEnablePersistentSecrets(false);
		if (ExtensionHelper::LoadExtension(db, "httpfs") != ExtensionLoadResult::LOADED_EXTENSION)
			throw std::runtime_error("httpfs unavailable");
		if (connection.Query("SET httpfs_client_implementation='curl'; SET http_timeout=5; SET http_retries=0;")
		        ->HasError())
			throw std::runtime_error("HTTP setup failed");
		auto owned = make_uniq<RestApiSecretStorage>(*db.instance, "");
		auto &storage = *owned;
		SecretManager::Get(*db.instance).LoadSecretStorage(std::move(owned));
		SecretType type;
		type.name = "owned_test";
		type.default_provider = "config";
		type.deserializer = KeyValueSecret::Deserialize<KeyValueSecret>;
		SecretManager::Get(*db.instance).RegisterSecretType(type);
		auto state = BoilstreamSessionPublicationTestAccess::Publish(storage, *connection.context, argv[1]);
		connection.BeginTransaction();
		auto transaction = CatalogTransaction::GetSystemCatalogTransaction(*connection.context);
		std::cout << "FIXTURE " << BoilstreamSessionPublicationTestAccess::Encode(storage) << std::endl;
		auto lookup = [&]() -> string {
			try {
				auto match = storage.LookupSecret("test://shared/object", "owned_test", &transaction);
				if (!match.HasMatch())
					return "absent";
				return static_cast<const KeyValueSecret &>(*match.secret_entry->secret).TryGetValue("key").ToString();
			} catch (...) {
				return "error";
			}
		};
		std::packaged_task<string()> first_task(lookup);
		auto first_result = first_task.get_future();
		std::thread first(std::move(first_task));
		JoinThread join_first {first};
		// The wrapper sends this only after request 1 reached its HTTP handler.
		std::string command;
		std::getline(std::cin, command);
		if (command != "start-second") {
			first.join();
			throw std::runtime_error("authority barrier failed");
		}
		std::promise<void> second_entered;
		auto second_started = second_entered.get_future();
		std::packaged_task<string()> second_task([&] {
			second_entered.set_value();
			return lookup();
		});
		auto second_result = second_task.get_future();
		std::thread second(std::move(second_task));
		JoinThread join_second {second};
		if (second_started.wait_for(std::chrono::seconds(2)) != std::future_status::ready)
			throw std::runtime_error("second worker did not start");
		const bool returned_early = second_result.wait_for(std::chrono::seconds(2)) == std::future_status::ready;
		bool cancelled_promptly = true;
		if (mode == "expired") {
			lock_guard<mutex> lock(state->session_lock);
			state->token_expires_at = std::chrono::system_clock::time_point::min();
		} else if (mode == "replaced") {
			BoilstreamSessionPublicationTestAccess::Publish(storage, *connection.context, argv[1]);
		} else if (mode == "generation") {
			state->authentication_generation.fetch_add(1);
		} else if (mode == "cancelled" || mode == "cancelled_cached") {
			if (mode == "cancelled_cached")
				BoilstreamSessionPublicationTestAccess::CacheKnownExpiry(storage, *state);
			connection.Interrupt();
			cancelled_promptly = second_result.wait_for(std::chrono::seconds(1)) == std::future_status::ready;
		}
		std::cout << (returned_early ? "SECOND_RETURNED" : "SECOND_PENDING") << std::endl;
		// The authority releases request 1 after observing the preceding line.
		first.join();
		second.join();
		const auto first_value = first_result.get();
		const auto second_value = second_result.get();
		const bool first_found = first_value == "synthetic-value";
		const bool second_found = second_value == "synthetic-value";
		const auto cache_count = state->secret_cache->Snapshot().size();
		const bool cache_expected = mode == "cancelled_cached" ? cache_count == 1 : cache_count == 0;
		bool recursive_absent = true, local_nonblocking = true;
		if (normal) {
			{
				BoilstreamConnectionState::SecretLookupGuard guard(*state);
				recursive_absent = guard.Acquired() && lookup() == "absent";
			}
			local_nonblocking = LocalGuardRemainsNonblocking();
			std::cout << "CASE first_lookup_succeeded " << (first_found ? "PASS" : "FAIL") << std::endl;
			std::cout << "CASE second_lookup_succeeded " << (second_found ? "PASS" : "FAIL") << std::endl;
			std::cout << "CASE same_thread_recursion_refused " << (recursive_absent ? "PASS" : "FAIL") << std::endl;
			std::cout << "CASE local_cross_thread_recursion_nonblocking " << (local_nonblocking ? "PASS" : "FAIL")
			          << std::endl;
		}
		const bool results = normal ? first_found && second_found : first_value == "absent" && second_value == "absent";
		const bool passed =
		    results && !returned_early && cache_expected && recursive_absent && local_nonblocking && cancelled_promptly;
		std::cout << "CASE queued_" << mode << " " << (passed ? "PASS" : "FAIL") << std::endl;
		std::cout << "CASE "
		          << (mode == "cancelled_cached" ? "cancelled_fresh_cache_not_exposed " : "unknown_expiry_not_cached ")
		          << (cache_expected && (mode != "cancelled_cached" || results) ? "PASS" : "FAIL") << std::endl;
		return passed ? 0 : 1;
	} catch (...) {
		// Never expose native/HTTP errors, even though this fixture is synthetic.
		std::cout << "CASE concurrent_lookup_setup FAIL" << std::endl;
		return 1;
	}
}
