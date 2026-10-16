// Exercise the real loader against a recording filesystem. No real token file,
// home directory, network service or authentication implementation is accessed.
#include "duckdb.hpp"
#include "duckdb/main/config.hpp"
#include "duckdb/common/file_system.hpp"
#include "boilstream_secret_storage.hpp"
#include <cstring>
#include <iostream>
#include <stdexcept>
using namespace duckdb;
class BoilstreamInputValidationTestAccess {
public:
 static bool Load(RestApiSecretStorage &storage, BoilstreamConnectionState &state) {
  return storage.LoadRefreshToken(state);
 }
 static void Save(RestApiSecretStorage &storage, BoilstreamConnectionState &state) {
  storage.SaveRefreshToken(state, true);
 }
};
class MemoryFS;
class MemoryHandle : public FileHandle {
public:
 MemoryHandle(MemoryFS &fs, const string &path, FileOpenFlags flags, string bytes);
 void Close() override;
 string bytes;
 bool closed = false;
};
class MemoryFS : public FileSystem {
public:
 string bytes, replacement;
 bool exists = true, directory_exists = true;
 int reads = 0, removals = 0, opens = 0, directory_creations = 0;
 int64_t size_override = -2;
 string GetName() const override { return "refresh-loader-fixture"; }
 bool DirectoryExists(const string &, optional_ptr<FileOpener>) override { return directory_exists; }
 void CreateDirectory(const string &, optional_ptr<FileOpener>) override { ++directory_creations; directory_exists = true; }
 bool FileExists(const string &, optional_ptr<FileOpener>) override { return exists; }
 void RemoveFile(const string &, optional_ptr<FileOpener>) override { ++removals; exists = false; }
 unique_ptr<FileHandle> OpenFile(const string &path, FileOpenFlags flags, optional_ptr<FileOpener>) override {
  ++opens;
  if (!exists) throw IOException("fixture file absent");
  return make_uniq<MemoryHandle>(*this, path, flags, bytes);
 }
 int64_t GetFileSize(FileHandle &handle) override {
  return size_override == -2 ? static_cast<int64_t>(static_cast<MemoryHandle &>(handle).bytes.size()) : size_override;
 }
 int64_t Read(FileHandle &handle, void *buffer, int64_t count) override {
  ++reads;
  auto &snapshot = static_cast<MemoryHandle &>(handle).bytes;
  auto copied = std::min<int64_t>(count, snapshot.size());
  std::memcpy(buffer, snapshot.data(), copied);
  return copied;
 }
};
MemoryHandle::MemoryHandle(MemoryFS &fs, const string &path, FileOpenFlags flags, string bytes)
 : FileHandle(fs, path, flags), bytes(std::move(bytes)) {}
void MemoryHandle::Close() {
 if (closed) return;
 closed = true;
 auto &fs = static_cast<MemoryFS &>(file_system);
 // Deterministically model an atomic replacement after this reader's snapshot.
 if (!fs.replacement.empty()) { fs.bytes = fs.replacement; fs.exists = true; }
}
struct Fixture {
 DuckDB db {nullptr};
 RestApiSecretStorage storage {*db.instance, "https://default.example/secrets"};
 unique_ptr<FileSystem> original;
 MemoryFS *fs;
 Fixture() {
  auto &config = DBConfig::GetConfig(*db.instance);
  original = std::move(config.file_system);
  auto memory = make_uniq<MemoryFS>(); fs = memory.get(); config.file_system = std::move(memory);
 }
 ~Fixture() { DBConfig::GetConfig(*db.instance).file_system = std::move(original); }
};
static string Record(const string &token = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
                     const string &endpoint = "https://saved.example/secrets",
                     const string &expiration = "2100-01-01T00:00:00Z") {
 return "{\"version\":1,\"refresh_token\":\"" + token + "\",\"endpoint_url\":\"" + endpoint +
   "\",\"region\":\"eu-west-1\",\"expires_at\":\"" + expiration + "\"}";
}
static void Require(bool value) { if (!value) throw std::runtime_error("assertion"); }
int main() {
 int failed = 0;
 auto test = [&](const char *name, auto fn) {
  try { fn(); std::cout << "CASE " << name << " PASS" << std::endl; }
  catch (...) { ++failed; std::cout << "CASE " << name << " FAIL" << std::endl; }
 };
 test("valid_record_loads_without_global_endpoint_change", [] {
  Fixture f; f.fs->bytes = Record(); BoilstreamConnectionState state;
  Require(BoilstreamInputValidationTestAccess::Load(f.storage, state));
  Require(state.refresh_token == vector<uint8_t>(32, 0));
  Require(state.GetEndpointUrl() == "https://saved.example/secrets" && state.region == "eu-west-1");
  Require(f.storage.GetEndpointUrl() == "https://default.example/secrets");
  Require(f.fs->reads == 1 && f.fs->removals == 0);
 });
 test("missing_record_does_not_create_directory", [] {
  Fixture f; f.fs->exists = false; f.fs->directory_exists = false; BoilstreamConnectionState state;
  Require(!BoilstreamInputValidationTestAccess::Load(f.storage, state));
  Require(f.fs->directory_creations == 0 && f.fs->opens == 0 && state.refresh_token.empty());
 });
 test("malformed_base64_is_a_clean_rejection", [] {
  Fixture f; f.fs->bytes = Record("%%%%"); BoilstreamConnectionState state;
  Require(!BoilstreamInputValidationTestAccess::Load(f.storage, state));
  Require(state.refresh_token.empty() && f.fs->removals == 0);
 });
 test("invalid_snapshot_cannot_delete_replacement", [] {
  Fixture f; f.fs->bytes = "{"; f.fs->replacement = Record(); BoilstreamConnectionState state;
  Require(!BoilstreamInputValidationTestAccess::Load(f.storage, state));
  Require(f.fs->exists && f.fs->bytes == f.fs->replacement && f.fs->removals == 0);
 });
 test("expired_snapshot_cannot_delete_replacement", [] {
  Fixture f; f.fs->bytes = Record("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", "https://old.example/secrets", "2000-01-01T00:00:00Z");
  f.fs->replacement = Record(); BoilstreamConnectionState state;
  Require(!BoilstreamInputValidationTestAccess::Load(f.storage, state));
  Require(f.fs->exists && f.fs->bytes == f.fs->replacement && f.fs->removals == 0);
 });
 test("maximum_size_record_is_accepted", [] {
  Fixture f; f.fs->bytes = Record(); f.fs->bytes.resize(65536, ' '); BoilstreamConnectionState state;
  Require(BoilstreamInputValidationTestAccess::Load(f.storage, state));
  Require(f.fs->reads == 1 && state.refresh_token.size() == 32 && f.fs->removals == 0);
 });
 test("oversized_save_preserves_existing_record", [] {
  Fixture f; f.fs->bytes = Record(); BoilstreamConnectionState state(string(65537, 'x'));
  state.refresh_token.assign(32, 0); state.region = "eu-west-1";
  state.token_expires_at = std::chrono::system_clock::now() + std::chrono::hours(2);
  bool rejected = false;
  try { BoilstreamInputValidationTestAccess::Save(f.storage, state); }
  catch (const IOException &) { rejected = true; }
  catch (...) { /* An unbounded writer reaches the intentionally unsupported Write seam. */ }
  Require(rejected && f.fs->removals == 0 && f.fs->opens == 0 && f.fs->bytes == Record());
 });
 test("oversized_record_rejected_before_read", [] {
  Fixture f; f.fs->bytes = Record(); f.fs->bytes.resize(65537, ' '); BoilstreamConnectionState state;
  Require(!BoilstreamInputValidationTestAccess::Load(f.storage, state));
  Require(f.fs->reads == 0 && state.refresh_token.empty());
 });
 test("embedded_nul_authority_rejected_without_truncation", [] {
  Fixture f; f.fs->bytes = Record("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", "https://saved.example/secrets\\u0000/other");
  BoilstreamConnectionState state;
  Require(!BoilstreamInputValidationTestAccess::Load(f.storage, state));
  Require(state.refresh_token.empty() && state.GetEndpointUrl().empty());
 });
 test("short_read_is_rejected", [] {
  Fixture f; f.fs->bytes = Record(); f.fs->size_override = f.fs->bytes.size() + 5;
  BoilstreamConnectionState state;
  Require(!BoilstreamInputValidationTestAccess::Load(f.storage, state));
  Require(state.refresh_token.empty() && f.fs->removals == 0);
 });
 test("negative_file_size_is_a_clean_rejection", [] {
  Fixture f; f.fs->bytes = Record(); f.fs->size_override = -1; BoilstreamConnectionState state;
  Require(!BoilstreamInputValidationTestAccess::Load(f.storage, state));
  Require(f.fs->reads == 0 && state.refresh_token.empty());
 });
 return failed ? 1 : 0;
}
