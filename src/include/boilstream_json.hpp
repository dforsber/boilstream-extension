#pragma once

#include "boilstream_security.hpp"
#include "yyjson.hpp"
#include <algorithm>
#include <limits>
#include <new>

namespace boilstream {

// Every yyjson allocation belongs to this scope. Normal yyjson frees erase it;
// exceptional exits reclaim and erase any allocations still owned by the scope.
// Documents must not outlive their arena. No global allocator or host change.
class JsonArena {
	struct alignas(std::max_align_t) Block {
		Block *previous;
		Block *next;
		size_t size;
	};

public:
	// The observer is used by regression tests to inspect bytes after erasure and
	// before deallocation. It must not throw or retain the pointer.
	using ErasureObserver = void (*)(const void *, size_t, void *) noexcept;
	explicit JsonArena(ErasureObserver observer = nullptr, void *observer_context = nullptr)
	    : observer(observer), observer_context(observer_context), allocator {Allocate, Reallocate, Free, this} {
	}
	~JsonArena() {
		while (head) {
			Free(this, head + 1);
		}
	}
	JsonArena(const JsonArena &) = delete;
	JsonArena &operator=(const JsonArena &) = delete;

	duckdb_yyjson::yyjson_doc *Read(const char *input, size_t size, duckdb_yyjson::yyjson_read_flag flags = 0) {
		// In-situ parsing would place secrets in caller-owned memory outside the
		// arena. All production calls use a copied input buffer.
		if (flags & duckdb_yyjson::YYJSON_READ_INSITU) {
			throw std::invalid_argument("In-situ JSON parsing is not supported");
		}
		// yyjson requires char*, but cannot mutate input without INSITU, rejected above.
		// NOLINTNEXTLINE(cppcoreguidelines-pro-type-const-cast)
		return duckdb_yyjson::yyjson_read_opts(const_cast<char *>(input), size, flags, &allocator, nullptr);
	}
	duckdb_yyjson::yyjson_mut_doc *New() {
		auto doc = duckdb_yyjson::yyjson_mut_doc_new(&allocator);
		if (!doc) {
			throw std::bad_alloc();
		}
		return doc;
	}
	const duckdb_yyjson::yyjson_alc &Allocator() const {
		return allocator;
	}

private:
	static void *Allocate(void *context, size_t size) noexcept {
		if (size > std::numeric_limits<size_t>::max() - sizeof(Block)) {
			return nullptr;
		}
		auto &arena = *static_cast<JsonArena *>(context);
		auto block = static_cast<Block *>(std::malloc(sizeof(Block) + size));
		if (!block) {
			return nullptr;
		}
		new (block) Block {nullptr, arena.head, size};
		if (arena.head) {
			arena.head->previous = block;
		}
		arena.head = block;
		return block + 1;
	}
	static void Free(void *context, void *pointer) noexcept {
		if (!pointer) {
			return;
		}
		auto &arena = *static_cast<JsonArena *>(context);
		auto block = static_cast<Block *>(pointer) - 1;
		if (block->previous) {
			block->previous->next = block->next;
		} else {
			arena.head = block->next;
		}
		if (block->next) {
			block->next->previous = block->previous;
		}
		const auto bytes = sizeof(Block) + block->size;
		WipeMemory(block, bytes);
		if (arena.observer) {
			arena.observer(block, bytes, arena.observer_context);
		}
		std::free(block);
	}
	static void *Reallocate(void *context, void *pointer, size_t, size_t size) noexcept {
		if (!pointer) {
			return Allocate(context, size);
		}
		if (!size) {
			Free(context, pointer);
			return nullptr;
		}
		auto replacement = Allocate(context, size);
		if (!replacement) {
			return nullptr; // Preserve the original allocation on failure.
		}
		const auto old_size = (static_cast<Block *>(pointer) - 1)->size;
		std::memcpy(replacement, pointer, std::min(old_size, size));
		Free(context, pointer);
		return replacement;
	}
	Block *head = nullptr;
	ErasureObserver observer;
	void *observer_context;
	duckdb_yyjson::yyjson_alc allocator;
};
} // namespace boilstream
