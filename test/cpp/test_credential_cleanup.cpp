#include "boilstream_json.hpp"
#include "boilstream_credential_stream.hpp"
#include "boilstream_http_cleanup.hpp"
#include <iostream>
#include <limits>
#include <stdexcept>

using namespace duckdb_yyjson;
static void Require(bool value) {
	if (!value)
		throw std::runtime_error("credential cleanup regression");
}
struct SimulatedFailure {};
struct Erasures {
	size_t count = 0;
	bool clean = true;
};
static void Observe(const void *data, size_t size, void *context) noexcept {
	auto &result = *static_cast<Erasures *>(context);
	++result.count;
	for (size_t i = 0; i < size; i++) {
		result.clean &= static_cast<const unsigned char *>(data)[i] == 0;
	}
}
int main() {
	Erasures erasures;
	{
		boilstream::JsonArena arena(Observe, &erasures);
		auto &allocator = arena.Allocator();
		auto bytes = allocator.malloc(allocator.ctx, 64);
		Require(bytes && reinterpret_cast<uintptr_t>(bytes) % alignof(std::max_align_t) == 0);
		std::memset(bytes, 0x73, 64);
		Require(!allocator.realloc(allocator.ctx, bytes, 64, std::numeric_limits<size_t>::max()));
		Require(static_cast<unsigned char *>(bytes)[63] == 0x73); // failure retains original
		bytes = allocator.realloc(allocator.ctx, bytes, 64, 128);
		Require(bytes && static_cast<unsigned char *>(bytes)[63] == 0x73);
		Require(erasures.count == 1 && erasures.clean); // old allocation scrubbed on growth
		allocator.free(allocator.ctx, bytes);
	}
	Require(erasures.count == 2 && erasures.clean);
	const std::string payload = "{\"password\":\"synthetic-secret\"}";
	{
		boilstream::JsonArena arena(Observe, &erasures);
		auto doc = arena.Read(payload.data(), payload.size());
		Require(doc && std::string(yyjson_get_str(yyjson_obj_get(yyjson_doc_get_root(doc), "password"))) ==
		                   "synthetic-secret");
		yyjson_doc_free(doc);                       // normal yyjson free must use the erasing allocator
		Require(!arena.Read("{\"password\":", 12)); // malformed JSON cleanup
	}
	auto before_exception = erasures.count;
	try {
		boilstream::JsonArena arena(Observe, &erasures);
		auto doc = arena.New();
		auto root = yyjson_mut_obj(doc);
		yyjson_mut_doc_set_root(doc, root);
		std::string large(20000, 's');
		Require(yyjson_mut_obj_add_strcpy(doc, root, "password", large.c_str()));
		throw SimulatedFailure {}; // no manual doc_free
	} catch (const SimulatedFailure &) {
	}
	Require(erasures.count > before_exception && erasures.clean);
	// Exercise the actual writer growing after it has already serialized a secret.
	{
		boilstream::JsonArena documents;
		auto doc = documents.New();
		auto root = yyjson_mut_obj(doc);
		yyjson_mut_doc_set_root(doc, root);
		const std::string first(20000, 'p'), second(100000, 't');
		Require(yyjson_mut_obj_add_strcpy(doc, root, "password", first.c_str()));
		Require(yyjson_mut_obj_add_strcpy(doc, root, "token", second.c_str()));
		auto before_writer = erasures.count;
		{
			boilstream::JsonArena writer(Observe, &erasures);
			size_t length = 0;
			auto encoded = yyjson_mut_write_opts(doc, 0, &writer.Allocator(), &length, nullptr);
			Require(encoded &&
			        std::string(encoded, length) == "{\"password\":\"" + first + "\",\"token\":\"" + second + "\"}");
			Require(erasures.count > before_writer && erasures.clean);
		}
		Require(erasures.count >= before_writer + 2 && erasures.clean);
	}
	auto before_stream = erasures.count;
	{
		boilstream::CredentialWriteStream stream(Observe, &erasures);
		const std::string first = "synthetic-binary-secret";
		const std::string next(20000, 's');
		stream.WriteData(reinterpret_cast<const unsigned char *>(first.data()), first.size());
		stream.WriteData(reinterpret_cast<const unsigned char *>(next.data()), next.size());
		Require(stream.GetPosition() == first.size() + next.size());
		Require(std::memcmp(stream.GetData(), first.data(), first.size()) == 0);
		Require(std::memcmp(stream.GetData() + first.size(), next.data(), next.size()) == 0);
		Require(erasures.count > before_stream && erasures.clean);
	}
	Require(erasures.count >= before_stream + 2 && erasures.clean);
	duckdb::HTTPHeaders provider;
	provider.Append("Set-Cookie", "session=first");
	provider.Append("Set-Cookie", "session=second");
	duckdb::HTTPHeaders owned;
	boilstream::CopyHeaders(provider, owned);
	Require(owned.GetHeaderValue("set-cookie") == "session=first");
	Require(owned.GetHeaderValues("set-cookie").size() == 1);
	try {
		boilstream::HeaderCleanup cleanup(owned);
		throw SimulatedFailure {};
	} catch (const SimulatedFailure &) {
	}
	for (const auto &header : owned) {
		Require(header.second.find_first_not_of('\0') == std::string::npos);
	}
	Require(provider.GetHeaderValues("set-cookie").size() == 2);
	Require(provider.GetHeaderValues("set-cookie")[0] == "session=first");
	Require(provider.GetHeaderValues("set-cookie")[1] == "session=second"); // do not mutate borrowed host state
	std::cout << "JSON allocation/reallocation, malformed and exceptional cleanup, and HTTP header ownership passed\n";
}
