// Actual session-publication boundary tests. Authentication completion is seeded;
// no OPAQUE acceptance or live-server qualification is claimed by this executable.
#include "duckdb.hpp"
#include "boilstream_secret_storage.hpp"
#include <iostream>
#include <stdexcept>
#include <thread>
#include <atomic>
using namespace duckdb;

class BoilstreamSessionPublicationTestAccess {
public:
	static void Publish(RestApiSecretStorage &s, ClientContext &ctx, shared_ptr<BoilstreamConnectionState> pending,
	                    shared_ptr<BoilstreamConnectionState> previous = nullptr, uint64_t generation = 0) {
		s.PublishSession(ctx, std::move(pending), previous, generation, false);
	}
};
static void Require(bool value) {
	if (!value)
		throw std::runtime_error("assertion");
}
static shared_ptr<BoilstreamConnectionState> Pending(const string &authority) {
	auto state = make_shared_ptr<BoilstreamConnectionState>(authority);
	state->access_token = "synthetic-publication-token";
	state->session_key.assign(32, 9);
	state->token_expires_at = std::chrono::system_clock::now() + std::chrono::hours(2);
	return state;
}
struct Fixture {
	DuckDB db {nullptr};
	RestApiSecretStorage storage {*db.instance, "https://default.invalid/secrets"};
	Connection connection {db};
};
int main() {
	int failed = 0;
	auto test = [&](const char *name, auto fn) {
		try {
			fn();
			std::cout << "CASE " << name << " PASS\n";
		} catch (...) {
			++failed;
			std::cout << "CASE " << name << " FAIL\n";
		}
	};
	test("replacement_retains_inflight_session", [] {
		Fixture f;
		auto &ctx = *f.connection.context;
		auto first = Pending("https://first.invalid/secrets");
		BoilstreamSessionPublicationTestAccess::Publish(f.storage, ctx, first);
		auto inflight = f.storage.GetSessionForConnection(ctx.GetConnectionId());
		auto second = Pending("https://second.invalid/secrets");
		BoilstreamSessionPublicationTestAccess::Publish(f.storage, ctx, second, first);
		Require(f.storage.GetSessionForConnection(ctx.GetConnectionId()) == second);
		Require(inflight == first && inflight->IsSessionTokenValid());
		Require(inflight->GetEndpointUrl() == "https://first.invalid/secrets");
		Require(f.storage.GetEndpointUrl(ctx) == "https://second.invalid/secrets");
		Require(f.storage.GetEndpointUrl() == "https://default.invalid/secrets");
	});
	test("stale_replacement_cannot_overwrite_newer_session", [] {
		Fixture f;
		auto &ctx = *f.connection.context;
		auto first = Pending("https://first.invalid/secrets");
		auto second = Pending("https://second.invalid/secrets");
		BoilstreamSessionPublicationTestAccess::Publish(f.storage, ctx, first);
		BoilstreamSessionPublicationTestAccess::Publish(f.storage, ctx, second, first);
		bool rejected = false;
		try {
			BoilstreamSessionPublicationTestAccess::Publish(f.storage, ctx, Pending("https://stale.invalid"), first);
		} catch (const IOException &) {
			rejected = true;
		}
		Require(rejected && f.storage.GetSessionForConnection(ctx.GetConnectionId()) == second);
	});
	test("logout_during_exchange_rejects_publication", [] {
		Fixture f;
		auto &ctx = *f.connection.context;
		auto first = Pending("https://first.invalid/secrets");
		BoilstreamSessionPublicationTestAccess::Publish(f.storage, ctx, first);
		const auto generation = first->authentication_generation.load();
		f.storage.ClearSession(ctx);
		bool rejected = false;
		try {
			BoilstreamSessionPublicationTestAccess::Publish(f.storage, ctx, Pending("https://new.invalid"), first,
			                                                generation);
		} catch (const IOException &) {
			rejected = true;
		}
		Require(rejected && !first->IsSessionTokenValid());
		Require(f.storage.GetSessionForConnection(ctx.GetConnectionId()) == first);
	});
	test("interruption_prevents_publication", [] {
		Fixture f;
		auto &ctx = *f.connection.context;
		ctx.interrupted = true;
		bool rejected = false;
		try {
			BoilstreamSessionPublicationTestAccess::Publish(f.storage, ctx, Pending("https://new.invalid"));
		} catch (const IOException &) {
			rejected = true;
		}
		ctx.interrupted = false;
		Require(rejected && !f.storage.GetSessionForConnection(ctx.GetConnectionId()));
	});
	test("connection_cleanup_releases_registry_not_inflight_request", [] {
		Fixture f;
		shared_ptr<BoilstreamConnectionState> inflight;
		idx_t id;
		{
			Connection connection(f.db);
			id = connection.context->GetConnectionId();
			BoilstreamSessionPublicationTestAccess::Publish(f.storage, *connection.context,
			                                                Pending("https://owned.invalid/secrets"));
			inflight = f.storage.GetSessionForConnection(id);
			Require(bool(inflight));
		}
		Require(!f.storage.GetSessionForConnection(id));
		Require(!f.storage.HasSession("@connection:" + std::to_string(id)));
		Require(inflight->IsSessionTokenValid() && inflight->GetEndpointUrl() == "https://owned.invalid/secrets");
	});
	test("capacity_rejection_preserves_live_mappings_and_recovers", [] {
		Fixture f;
		auto &ctx = *f.connection.context;
		f.storage.GetOrCreateSession("capacity-fixture");
		for (idx_t i = 1000000; i < 1010000; ++i)
			f.storage.SetActiveSessionKeyForConnection(i, "capacity-fixture");
		bool rejected = false;
		try {
			BoilstreamSessionPublicationTestAccess::Publish(f.storage, ctx, Pending("https://new.invalid"));
		} catch (const IOException &) {
			rejected = true;
		}
		Require(rejected);
		Require(bool(f.storage.GetSessionForConnection(1000000)) && bool(f.storage.GetSessionForConnection(1009999)));
		f.storage.ClearConnectionMapping(1000000);
		auto accepted = Pending("https://accepted.invalid/secrets");
		BoilstreamSessionPublicationTestAccess::Publish(f.storage, ctx, accepted);
		Require(f.storage.GetSessionForConnection(ctx.GetConnectionId()) == accepted);
	});
	test("parallel_connections_publish_distinct_authorities", [] {
		Fixture f;
		vector<unique_ptr<Connection>> connections;
		for (int i = 0; i < 16; ++i)
			connections.push_back(make_uniq<Connection>(f.db));
		std::atomic<int> ready {0}, errors {0};
		std::atomic<bool> start {false};
		std::vector<std::thread> threads;
		for (int i = 0; i < 16; ++i)
			threads.emplace_back([&, i] {
				ready.fetch_add(1);
				while (!start.load())
					std::this_thread::yield();
				try {
					BoilstreamSessionPublicationTestAccess::Publish(
					    f.storage, *connections[i]->context,
					    Pending("https://session" + std::to_string(i) + ".invalid/secrets"));
				} catch (...) {
					errors.fetch_add(1);
				}
			});
		while (ready.load() != 16)
			std::this_thread::yield();
		start = true;
		for (auto &thread : threads)
			thread.join();
		Require(errors.load() == 0);
		for (int i = 0; i < 16; ++i) {
			auto state = f.storage.GetSessionForConnection(connections[i]->context->GetConnectionId());
			Require(state && state->IsSessionTokenValid());
			Require(state->GetEndpointUrl() == "https://session" + std::to_string(i) + ".invalid/secrets");
		}
	});
	return failed ? 1 : 0;
}
