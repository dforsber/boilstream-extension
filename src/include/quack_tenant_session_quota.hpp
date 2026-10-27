#pragma once
#include <cstdint>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <unordered_map>

namespace duckdb {
class QuackRequesterTenant {
  public:
	explicit QuackRequesterTenant(uint32_t value) : value(value) {
		if (!value)
			throw std::invalid_argument("Missing authenticated requester tenant");
	}
	uint32_t Value() const noexcept { return value; }
	bool operator==(QuackRequesterTenant other) const noexcept { return value == other.value; }

  private:
	uint32_t value;
};

// Admission only: no mutex/counter operations on FETCH. A shared lease survives
// context replacement and is released only after the last session borrower.
class QuackTenantSessionQuota : public std::enable_shared_from_this<QuackTenantSessionQuota> {
  public:
	class Lease {
	  public:
		Lease(std::shared_ptr<QuackTenantSessionQuota> owner, QuackRequesterTenant tenant)
			: owner(std::move(owner)), tenant(tenant) {}
		~Lease() {
			if (admitted)
				owner->Release(tenant);
		}
		Lease(const Lease &) = delete;
		Lease &operator=(const Lease &) = delete;
		QuackRequesterTenant Tenant() const noexcept { return tenant; }

	  private:
		friend class QuackTenantSessionQuota;
		std::shared_ptr<QuackTenantSessionQuota> owner;
		const QuackRequesterTenant tenant;
		bool admitted = false;
	};
	std::shared_ptr<Lease> Acquire(QuackRequesterTenant tenant, uint32_t limit) {
		if (!limit)
			throw std::invalid_argument("Invalid tenant session limit");
		auto lease = std::make_shared<Lease>(shared_from_this(), tenant);
		{
			std::lock_guard<std::mutex> guard(mutex);
			auto found = counts.find(tenant.Value());
			if (found != counts.end() && found->second >= limit)
				return nullptr;
			auto inserted = counts.emplace(tenant.Value(), 0).first;
			++inserted->second;
			lease->admitted = true;
		}
		return lease;
	}

  private:
	void Release(QuackRequesterTenant tenant) noexcept {
		std::lock_guard<std::mutex> guard(mutex);
		auto found = counts.find(tenant.Value());
		if (--found->second == 0)
			counts.erase(found);
	}
	std::mutex mutex;
	std::unordered_map<uint32_t, uint32_t> counts;
};
} // namespace duckdb
