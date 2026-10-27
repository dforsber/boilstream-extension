#pragma once
#include "quack_tenant_session_quota.hpp"
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <utility>

namespace duckdb {
struct SessionCtx;
// Registry ownership only. Authentication/callbacks/destruction run outside mutex.
template <class Context> struct BasicSessionRegistry {
	struct Admission {
		explicit Admission(std::string id) : id(std::move(id)) {}
		const std::string id;
		std::shared_ptr<const Context> published;
	};
	std::mutex mutex;
	std::unordered_map<std::string, std::shared_ptr<const Context>> sessions;
	std::unordered_map<std::string, Admission *> pending;
	std::shared_ptr<QuackTenantSessionQuota> quotas = std::make_shared<QuackTenantSessionQuota>();

	std::shared_ptr<QuackTenantSessionQuota::Lease> ReserveQuota(const std::string &id, QuackRequesterTenant tenant,
																 uint32_t limit) {
		std::lock_guard<std::mutex> guard(mutex);
		auto found = sessions.find(id);
		if (found != sessions.end() && found->second->session_quota) {
			const auto &lease = found->second->session_quota;
			// Reauthentication cannot change charging authority or double-charge.
			return lease->Tenant() == tenant ? lease : nullptr;
		}
		return quotas->Acquire(tenant, limit);
	}

	std::unique_ptr<Admission> Begin(const std::string &id) {
		auto owner = std::make_unique<Admission>(id);
		{
			std::lock_guard<std::mutex> guard(mutex);
			if (sessions.count(id) || pending.count(id))
				return nullptr;
			pending.emplace(id, owner.get());
		}
		return owner;
	}
	void Publish(const std::string &id, std::shared_ptr<const Context> context) {
		std::shared_ptr<const Context> retired, previous_admission;
		{
			std::lock_guard<std::mutex> guard(mutex);
			auto existing = sessions.find(id);
			if (existing != sessions.end() && existing->second->session_quota &&
				existing->second->session_quota != context->session_quota)
				throw std::invalid_argument("Session charging authority changed");
			auto &slot = sessions[id];
			retired = std::move(slot);
			slot = std::move(context);
			auto admission = pending.find(id);
			if (admission != pending.end()) {
				previous_admission = std::move(admission->second->published);
				admission->second->published = slot;
			}
		}
	}
	void Finish(std::unique_ptr<Admission> owner, bool committed) {
		std::shared_ptr<const Context> retired;
		{
			std::lock_guard<std::mutex> guard(mutex);
			auto admission = pending.find(owner->id);
			if (admission == pending.end() || admission->second != owner.get())
				return;
			if (!committed && owner->published) {
				auto found = sessions.find(owner->id);
				if (found != sessions.end() && found->second == owner->published) {
					retired = std::move(found->second);
					sessions.erase(found);
				}
			}
			pending.erase(admission);
		}
	}
	void Retire(const std::string &id) {
		std::shared_ptr<const Context> retired;
		{
			std::lock_guard<std::mutex> guard(mutex);
			auto found = sessions.find(id);
			if (found != sessions.end()) {
				retired = std::move(found->second);
				sessions.erase(found);
			}
		}
	}
};
using SessionRegistry = BasicSessionRegistry<SessionCtx>;
} // namespace duckdb
