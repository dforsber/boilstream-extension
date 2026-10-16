#pragma once

#include "duckdb/main/secret/secret_manager.hpp"
#include "duckdb/common/case_insensitive_map.hpp"
#include "duckdb/common/mutex.hpp"
#include <chrono>

namespace duckdb {

// One authenticated owner (or one explicitly local connection) owns this cache.
// Immutable entries keep readers alive across replacement; no credential copies,
// serialization, network operations or destruction occur under the cache lock.
class BoilstreamSecretCache {
public:
	using Time = std::chrono::system_clock::time_point;
	struct Entry {
		shared_ptr<const SecretEntry> secret;
		Time expires;
		idx_t bytes;
	};
	using Entries = case_insensitive_map_t<Entry>;
	static constexpr idx_t MAX_ENTRIES = 10000;
	static constexpr idx_t MAX_BYTES = 10 * 1024 * 1024;
	static constexpr idx_t MAX_ENTRY_BYTES = 1024 * 1024;

	static Entry Prepare(unique_ptr<const BaseSecret> secret, Time expires, idx_t bytes) {
		if (!secret || secret->GetName().empty() || (bytes == 0 || bytes > MAX_ENTRY_BYTES)) {
			throw InvalidInputException("Invalid or oversized BoilStream secret");
		}
		auto entry = make_shared_ptr<SecretEntry>(std::move(secret));
		// Preserve the storage backend contract used by DuckDB DROP filtering.
		// PERSISTENT denotes the REST backend, not a local credential file.
		entry->persist_type = SecretPersistType::PERSISTENT;
		entry->storage_mode = "boilstream";
		return {std::move(entry), expires, bytes};
	}

	uint64_t Revision() {
		lock_guard<mutex> guard(lock);
		return revision;
	}
	bool IsClosed() {
		lock_guard<mutex> guard(lock);
		return closed;
	}
	bool RecentlyFetched() {
		lock_guard<mutex> guard(lock);
		return !closed && fetched != std::chrono::steady_clock::time_point::min() &&
		       std::chrono::steady_clock::now() - fetched < std::chrono::seconds(10);
	}

	shared_ptr<const SecretEntry> Get(const string &name, bool allow_expired = false) {
		lock_guard<mutex> guard(lock);
		auto it = entries.find(name);
		if (closed || it == entries.end() || (!allow_expired && !Fresh(it->second))) return nullptr;
		return it->second.secret;
	}
	vector<shared_ptr<const SecretEntry>> Snapshot(bool allow_expired = false) {
		vector<shared_ptr<const SecretEntry>> result;
		lock_guard<mutex> guard(lock);
		if (!closed) {
			result.reserve(entries.size());
			for (auto &it : entries) if (allow_expired || Fresh(it.second)) result.push_back(it.second.secret);
		}
		return result;
	}
	Time Expiration(const string &name) {
		lock_guard<mutex> guard(lock);
		auto it = entries.find(name);
		return closed || it == entries.end() ? Time::min() : it->second.expires;
	}

	void ValidatePut(const Entry &entry, uint64_t expected) {
		lock_guard<mutex> guard(lock);
		CheckAdmission(entry, expected);
	}
	void Put(Entry entry, uint64_t expected) {
		const auto name = entry.secret->secret->GetName();
		Entry retired;
		{
			lock_guard<mutex> guard(lock);
			CheckAdmission(entry, expected);
			auto it = entries.find(name);
			const auto old_bytes = it == entries.end() ? 0 : it->second.bytes;
			if (it == entries.end()) {
				entries.emplace(name, entry);
			} else {
				retired = std::move(it->second);
				it->second = entry;
			}
			bytes = bytes - old_bytes + entry.bytes;
			++revision;
			fetched = std::chrono::steady_clock::time_point::min();
		}
	}
	void Replace(Entries replacement, uint64_t expected) {
		idx_t total = 0;
		if (replacement.size() > MAX_ENTRIES) throw IOException("Too many BoilStream secrets");
		for (const auto &it : replacement) {
			if (it.second.bytes > MAX_ENTRY_BYTES || it.second.bytes > MAX_BYTES - total)
				throw IOException("BoilStream secret cache capacity exhausted");
			total += it.second.bytes;
		}
		{
			lock_guard<mutex> guard(lock);
			CheckRevision(expected);
			entries.swap(replacement);
			bytes = total;
			++revision;
			fetched = std::chrono::steady_clock::now();
		}
	}
	void Remove(const string &name, uint64_t expected) {
		Entry retired;
		{
			lock_guard<mutex> guard(lock);
			CheckRevision(expected);
			auto it = entries.find(name);
			if (it != entries.end()) {
				bytes -= it->second.bytes;
				retired = std::move(it->second);
				entries.erase(it);
			}
			++revision;
			fetched = std::chrono::steady_clock::time_point::min();
		}
	}
	void SetExpiration(const string &name, Time expires) {
		lock_guard<mutex> guard(lock);
		auto it = entries.find(name);
		if (!closed && it != entries.end()) {
			it->second.expires = expires;
			++revision;
			fetched = std::chrono::steady_clock::time_point::min();
		}
	}
	void Close() {
		Entries retired;
		{
			lock_guard<mutex> guard(lock);
			closed = true;
			++revision;
			bytes = 0;
			entries.swap(retired);
		}
	}
private:
	static bool Fresh(const Entry &entry) {
		return entry.expires > std::chrono::system_clock::now() + std::chrono::minutes(5);
	}
	void CheckRevision(uint64_t expected) {
		if (closed || revision != expected) throw IOException("BoilStream secret update was superseded");
	}
	void CheckAdmission(const Entry &entry, uint64_t expected) {
		CheckRevision(expected);
		auto it = entries.find(entry.secret->secret->GetName());
		const auto old_bytes = it == entries.end() ? 0 : it->second.bytes;
		if (entry.bytes > MAX_ENTRY_BYTES || (it == entries.end() && entries.size() >= MAX_ENTRIES) ||
		    entry.bytes > MAX_BYTES - (bytes - old_bytes)) {
			throw IOException("BoilStream secret cache capacity exhausted");
		}
	}
	mutex lock;
	Entries entries;
	idx_t bytes = 0;
	uint64_t revision = 0;
	bool closed = false;
	std::chrono::steady_clock::time_point fetched = std::chrono::steady_clock::time_point::min();
};
} // namespace duckdb
