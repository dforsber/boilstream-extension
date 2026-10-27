#pragma once
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <utility>

namespace duckdb {
struct SessionCtx;
// Registry ownership only. Authentication/callbacks/destruction run outside mutex.
struct SessionRegistry {
	struct Admission {
		explicit Admission(std::string id) : id(std::move(id)) {}
		const std::string id;
		std::shared_ptr<const SessionCtx> published;
	};
	std::mutex mutex;
	std::unordered_map<std::string, std::shared_ptr<const SessionCtx>> sessions;
	std::unordered_map<std::string, Admission *> pending;

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
	void Publish(const std::string &id, std::shared_ptr<const SessionCtx> context) {
		std::shared_ptr<const SessionCtx> retired, previous_admission;
		{
			std::lock_guard<std::mutex> guard(mutex);
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
		std::shared_ptr<const SessionCtx> retired;
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
		std::shared_ptr<const SessionCtx> retired;
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
} // namespace duckdb
