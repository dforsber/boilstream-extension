#pragma once

#include "boilstream_json.hpp"
#include "duckdb/common/serializer/write_stream.hpp"

namespace boilstream {

// BinarySerializer can grow its output while it contains secret material. Use
// the erasing allocator for both retired buffers and the final owned buffer.
class CredentialWriteStream : public duckdb::WriteStream {
public:
	explicit CredentialWriteStream(JsonArena::ErasureObserver observer = nullptr, void *context = nullptr)
	    : arena(observer, context) {
	}
	void WriteData(duckdb::const_data_ptr_t input, duckdb::idx_t size) override {
		if (size > std::numeric_limits<size_t>::max() - position) {
			throw std::bad_alloc();
		}
		const size_t required = position + size;
		if (required > capacity) {
			const auto next = required <= std::numeric_limits<size_t>::max() / 2 ? required * 2 : required;
			auto &allocator = arena.Allocator();
			auto replacement = allocator.realloc(allocator.ctx, data, capacity, next);
			if (!replacement) {
				throw std::bad_alloc();
			}
			data = static_cast<duckdb::data_ptr_t>(replacement);
			capacity = next;
		}
		if (size) {
			std::memcpy(data + position, input, size);
		}
		position = required;
	}
	duckdb::data_ptr_t GetData() const {
		return data;
	}
	size_t GetPosition() const {
		return position;
	}

private:
	JsonArena arena;
	duckdb::data_ptr_t data = nullptr;
	size_t position = 0;
	size_t capacity = 0;
};
} // namespace boilstream
