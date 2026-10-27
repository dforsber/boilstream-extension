#include "quack_session_admission_registry.hpp"
#include <atomic>
#include <iostream>
#include <thread>
#include <vector>
struct Context {
	std::shared_ptr<duckdb::QuackTenantSessionQuota::Lease> session_quota;
};
using Registry = duckdb::BasicSessionRegistry<Context>;
using Tenant = duckdb::QuackRequesterTenant;
unsigned checks = 0;
void Require(bool value, const char *message) {
	if (!value)
		throw std::runtime_error(message);
	++checks;
}
int main() {
	try {
		bool zero = false;
		try {
			Tenant invalid(0);
		} catch (const std::invalid_argument &) {
			zero = true;
		}
		Require(zero, "zero tenant accepted");
		auto quotas = std::make_shared<duckdb::QuackTenantSessionQuota>();
		auto a = quotas->Acquire(Tenant(11), 1);
		Require(bool(a) && !quotas->Acquire(Tenant(11), 1), "tenant limit not enforced");
		auto b = quotas->Acquire(Tenant(22), 1);
		Require(bool(b), "independent tenant blocked");
		auto borrower = a;
		a.reset();
		Require(!quotas->Acquire(Tenant(11), 1), "borrower released charge early");
		borrower.reset();
		Require(bool(quotas->Acquire(Tenant(11), 1)), "last borrower leaked charge");
		Registry registry;
		auto opening = registry.Begin("session");
		auto first = std::make_shared<Context>();
		first->session_quota = registry.ReserveQuota("session", Tenant(11), 1);
		registry.Publish("session", first);
		registry.Finish(std::move(opening), true);
		auto next = std::make_shared<Context>();
		next->session_quota = registry.ReserveQuota("session", Tenant(11), 1);
		Require(next->session_quota == first->session_quota, "reauthentication double-charged");
		Require(!registry.ReserveQuota("session", Tenant(22), 1), "reauthentication changed tenant");
		registry.Publish("session", next);
		bool downgrade = false;
		try {
			registry.Publish("session", std::make_shared<Context>());
		} catch (const std::invalid_argument &) {
			downgrade = true;
		}
		Require(downgrade, "legacy context removed a live charge");
		registry.Retire("session");
		next.reset();
		Require(!registry.ReserveQuota("other", Tenant(11), 1), "retained native borrower uncharged");
		first.reset();
		Require(bool(registry.ReserveQuota("other", Tenant(11), 1)), "retirement retained charge");
		{
			auto admission = registry.Begin("failed");
			auto failed = std::make_shared<Context>();
			failed->session_quota = registry.ReserveQuota("failed", Tenant(11), 1);
			registry.Publish("failed", failed);
			failed.reset();
			registry.Finish(std::move(admission), false);
			Require(bool(registry.ReserveQuota("after-failure", Tenant(11), 1)), "rollback leaked charge");
		}
		std::atomic<bool> start{false};
		std::atomic<unsigned> ready{0}, admitted{0};
		std::vector<std::thread> threads;
		std::vector<std::shared_ptr<duckdb::QuackTenantSessionQuota::Lease>> retained(16);
		for (size_t i = 0; i < retained.size(); ++i)
			threads.emplace_back([&, i] {
				++ready;
				while (!start.load())
					std::this_thread::yield();
				retained[i] = quotas->Acquire(Tenant(33), 3);
				if (retained[i])
					++admitted;
			});
		while (ready != retained.size())
			std::this_thread::yield();
		start = true;
		for (auto &thread : threads)
			thread.join();
		Require(admitted == 3, "concurrent admission exceeded or lost capacity");
		retained.clear();
		Require(bool(quotas->Acquire(Tenant(33), 1)), "concurrent owners leaked charge");
		std::cout << checks << " tenant session quota checks passed\n";
	} catch (const std::exception &error) {
		std::cerr << error.what() << '\n';
		return 1;
	}
}
