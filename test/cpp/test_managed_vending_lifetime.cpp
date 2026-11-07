// Actual signed HTTP response -> public client managed vend/named lookup.
// Synthetic session material is fixture setup, not evidence of OPAQUE login.
#include "duckdb.hpp"
#include "duckdb/main/config.hpp"
#include "boilstream_secret_storage.hpp"
#include "client_test_context.hpp"
#include <future>
#include <iostream>
#include <thread>
using namespace duckdb;

class BoilstreamSessionPublicationTestAccess {
public:
	static shared_ptr<BoilstreamConnectionState> Publish(RestApiSecretStorage &storage, ClientContext &context,
	                                                     const string &endpoint) {
		auto state = make_shared_ptr<BoilstreamConnectionState>(endpoint);
		state->session_key.assign(64, 7);
		state->access_token.assign(64, 'a');
		state->region = "synthetic-region";
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
		if (thread.joinable()) {
			thread.join();
		}
	}
};
static void Require(bool value) {
	if (!value) {
		throw std::runtime_error("managed fixture assertion");
	}
}
int main(int argc, char **argv) {
	if (argc != 4) {
		return 2;
	}
	try {
		const string lane = argv[2], mode = argv[3];
		Require(lane == "vend" || lane == "named");
		Require(mode == "normal" || mode == "generation" || mode == "replaced" || mode == "cancelled" ||
		        mode == "expired" || mode == "logout");
		const string catalog = "9a927d1b-30f5-48da-91eb-af1492bf31c0";
		const string scope = ManagedCatalogSecretScope("server.example:443", catalog);
		const string name = "__quack__" + scope;
		Config config;
		DuckDB db(nullptr, &config);
		Connection original(db), fresh(db);
		SecretManager::Get(*db.instance).SetEnablePersistentSecrets(false);
		LoadTestHttpfs(original);
		for (auto *connection : {&original, &fresh}) {
			Require(
			    !connection->Query("SET httpfs_client_implementation='curl'; SET http_timeout=5; SET http_retries=0;")
			         ->HasError());
		}
		auto owned = make_uniq<RestApiSecretStorage>(*db.instance, "");
		auto &storage = *owned;
		SecretManager::Get(*db.instance).LoadSecretStorage(std::move(owned));
		auto state = BoilstreamSessionPublicationTestAccess::Publish(storage, *original.context, argv[1]);
		original.BeginTransaction();
		auto transaction = CatalogTransaction::GetSystemCatalogTransaction(*original.context);
		auto named_token = [&](CatalogTransaction &tx) -> string {
			auto entry = storage.GetSecretByName(name, &tx);
			if (!entry) {
				return "absent";
			}
			Require(entry->secret->GetType() == "quack");
			const auto &secret = static_cast<const KeyValueSecret &>(*entry->secret);
			Require(secret.TryGetValue("catalog_id").ToString() == catalog);
			Require(secret.TryGetValue("endpoint").ToString() == "server.example:443");
			return secret.TryGetValue("token").ToString();
		};
		std::packaged_task<string()> request([&]() -> string {
			try {
				if (lane == "vend") {
					auto credential = storage.VendManagedCatalogCredential(catalog, &transaction);
					Require(credential.catalog_id == catalog && credential.endpoint == "server.example:443");
					return credential.token;
				}
				return named_token(transaction);
			} catch (...) {
				return "absent";
			}
		});
		auto result = request.get_future();
		std::thread worker(std::move(request));
		JoinThread join {worker};
		std::cout << "READY" << std::endl;
		// Python sends this only after the actual credential GET is held.
		string command;
		std::getline(std::cin, command);
		Require(command == "mutate-held");
		Require(result.wait_for(std::chrono::milliseconds(0)) != std::future_status::ready);
		if (mode == "generation") {
			state->authentication_generation.fetch_add(1);
		} else if (mode == "replaced") {
			BoilstreamSessionPublicationTestAccess::Publish(storage, *original.context, argv[1]);
		} else if (mode == "cancelled") {
			original.Interrupt();
		} else if (mode == "logout") {
			storage.ClearSession(*original.context);
		} else if (mode == "expired") {
			lock_guard<mutex> lock(state->session_lock);
			state->token_expires_at = std::chrono::system_clock::time_point::min();
		}
		std::cout << "HELD_MUTATION_APPLIED" << std::endl;
		// The independent authority releases its signed response after this line.
		Require(result.wait_for(std::chrono::seconds(10)) == std::future_status::ready);
		const auto returned = result.get();
		worker.join();
		Require(returned == (mode == "normal" ? "synthetic-old-token" : "absent"));
		ManagedCatalogCredentialEnvelope cached;
		const bool has_cached = state->TryGetManagedCatalogCredential(scope, cached);
		Require(has_cached == (mode == "normal"));
		if (has_cached) {
			Require(cached.token == "synthetic-old-token");
			Require(named_token(transaction) == "synthetic-old-token"); // No additional GET.
		}
		// Same database, same scope, independent live owner. It must still vend,
		// and must receive the second authority response rather than old cache A.
		auto peer = BoilstreamSessionPublicationTestAccess::Publish(storage, *fresh.context, argv[1]);
		fresh.BeginTransaction();
		auto peer_tx = CatalogTransaction::GetSystemCatalogTransaction(*fresh.context);
		Require(named_token(peer_tx) == "synthetic-fresh-token");
		ManagedCatalogCredentialEnvelope peer_cached;
		Require(peer->TryGetManagedCatalogCredential(scope, peer_cached));
		Require(peer_cached.token == "synthetic-fresh-token");
		std::cout << "CASE held_" << lane << "_" << mode << " PASS" << std::endl;
		std::cout << "CASE fresh_owner_" << lane << "_" << mode << " PASS" << std::endl;
		return 0;
	} catch (...) {
		std::cout << "CASE managed_lifetime_setup FAIL" << std::endl;
		return 1;
	}
}
