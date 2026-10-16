// Exercise actual publication/resume boundaries with a filesystem tripwire.
// Authentication completion is seeded; failed resume uses a loopback rejection
// server supplied by the runner. Never accesses a real credential file.
#include "duckdb.hpp"
#include "duckdb/main/config.hpp"
#include "duckdb/common/file_system.hpp"
#include "boilstream_secret_storage.hpp"
#include <atomic>
#include <iostream>
#include <stdexcept>
#include <thread>
using namespace duckdb;

class BoilstreamSessionPublicationTestAccess {
public:
 static void Publish(RestApiSecretStorage &storage, ClientContext &context,
                     shared_ptr<BoilstreamConnectionState> state, bool supports_resume = true) {
  storage.PublishSession(context, std::move(state), nullptr, 0, supports_resume);
 }
};
static void Require(bool value) { if (!value) throw std::runtime_error("assertion"); }
class TripwireFS : public FileSystem {
public:
 std::atomic<int> accesses {0};
 string GetName() const override { return "memory-only-session-tripwire"; }
 bool DirectoryExists(const string &, optional_ptr<FileOpener>) override { ++accesses; return true; }
 bool FileExists(const string &, optional_ptr<FileOpener>) override { ++accesses; return true; }
 void CreateDirectory(const string &, optional_ptr<FileOpener>) override { ++accesses; throw IOException("tripwire"); }
 void RemoveFile(const string &, optional_ptr<FileOpener>) override { ++accesses; throw IOException("tripwire"); }
 unique_ptr<FileHandle> OpenFile(const string &, FileOpenFlags, optional_ptr<FileOpener>) override {
  ++accesses; throw IOException("tripwire");
 }
};
struct Fixture {
 DuckDB db {nullptr};
 RestApiSecretStorage storage {*db.instance, "http://127.0.0.1:1/unused-default"};
 Connection connection {db};
 unique_ptr<FileSystem> original;
 TripwireFS *fs;
 Fixture() {
  auto &config = DBConfig::GetConfig(*db.instance);
  original = std::move(config.file_system);
  auto tripwire = make_uniq<TripwireFS>(); fs = tripwire.get(); config.file_system = std::move(tripwire);
 }
 ~Fixture() { DBConfig::GetConfig(*db.instance).file_system = std::move(original); }
};
static shared_ptr<BoilstreamConnectionState> Pending(const string &endpoint = "https://session.invalid/secrets") {
 auto state = make_shared_ptr<BoilstreamConnectionState>(endpoint);
 state->access_token = "synthetic-access-token";
 state->bootstrap_token_hash = "synthetic-bootstrap-identity";
 state->session_key.assign(32, 7);
 state->refresh_token.assign(32, 9);
 state->region = "eu-west-1";
 state->token_expires_at = std::chrono::system_clock::now() + std::chrono::hours(2);
 return state;
}
static void RejectResume(Fixture &f, ClientContext &context) {
 bool rejected = false;
 try { f.storage.PerformOpaqueResume(context); }
 catch (const IOException &) { rejected = true; }
 Require(rejected && f.fs->accesses.load() == 0);
}
int main(int argc, char **argv) {
 if (argc != 2) return 2;
 int failed = 0;
 auto test = [&](const char *name, auto fn) {
  try { fn(); std::cout << "CASE " << name << " PASS" << std::endl; }
  catch (...) { ++failed; std::cout << "CASE " << name << " FAIL" << std::endl; }
 };
 test("disabled_resume_still_publishes_valid_session_control", [] {
  Fixture f; auto state = Pending();
  BoilstreamSessionPublicationTestAccess::Publish(f.storage, *f.connection.context, state, false);
  Require(f.storage.GetSessionForConnection(f.connection.context->GetConnectionId()) == state);
  Require(state->IsSessionTokenValid() && f.fs->accesses.load() == 0);
 });
 test("server_capability_never_authorizes_file_access", [] {
  Fixture f; auto state = Pending();
  BoilstreamSessionPublicationTestAccess::Publish(f.storage, *f.connection.context, state);
  Require(state->IsSessionTokenValid() && state->refresh_token == vector<uint8_t>(32, 9));
  Require(f.storage.GetSessionForConnection(f.connection.context->GetConnectionId()) == state);
  Require(f.fs->accesses.load() == 0);
 });
 test("disabled_resume_discards_unusable_refresh_credential", [] {
  Fixture f; auto state = Pending();
  BoilstreamSessionPublicationTestAccess::Publish(f.storage, *f.connection.context, state, false);
  Require(state->refresh_token.empty() && f.fs->accesses.load() == 0);
 });
 test("fresh_connection_cannot_load_ambient_credentials", [] {
  Fixture f; RejectResume(f, *f.connection.context);
  Require(!f.storage.GetSessionForConnection(f.connection.context->GetConnectionId()));
 });
 test("another_connection_cannot_borrow_owned_credentials", [] {
  Fixture f; Connection other(f.db); auto state = Pending();
  BoilstreamSessionPublicationTestAccess::Publish(f.storage, *f.connection.context, state);
  f.fs->accesses = 0; RejectResume(f, *other.context);
  Require(f.storage.GetSessionForConnection(f.connection.context->GetConnectionId()) == state);
  Require(!f.storage.GetSessionForConnection(other.context->GetConnectionId()));
 });
 test("expired_refresh_requires_login_without_io", [] {
  Fixture f; auto state = Pending(); state->token_expires_at = std::chrono::system_clock::now() - std::chrono::hours(1);
  BoilstreamSessionPublicationTestAccess::Publish(f.storage, *f.connection.context, state);
  f.fs->accesses = 0; RejectResume(f, *f.connection.context);
  Require(f.storage.GetSessionForConnection(f.connection.context->GetConnectionId()) == state);
 });
 test("invalid_refresh_size_requires_login_without_io", [] {
  Fixture f; auto state = Pending(); state->refresh_token.resize(31);
  BoilstreamSessionPublicationTestAccess::Publish(f.storage, *f.connection.context, state);
  f.fs->accesses = 0; RejectResume(f, *f.connection.context);
 });
 test("logout_cannot_restore_credentials_from_disk", [] {
  Fixture f; auto state = Pending();
  BoilstreamSessionPublicationTestAccess::Publish(f.storage, *f.connection.context, state);
  f.storage.ClearSession(*f.connection.context); f.fs->accesses = 0;
  RejectResume(f, *f.connection.context);
  Require(state->refresh_token.empty() && state->session_key.empty() && state->access_token.empty());
 });
 test("closed_connection_cannot_restore_credentials", [] {
  Fixture f; idx_t closed_id;
  { Connection closed(f.db); closed_id = closed.context->GetConnectionId();
    BoilstreamSessionPublicationTestAccess::Publish(f.storage, *closed.context, Pending()); }
  f.fs->accesses = 0; RejectResume(f, *f.connection.context);
  Require(!f.storage.GetSessionForConnection(closed_id));
 });
 test("parallel_publication_keeps_credentials_in_memory", [] {
  Fixture f; vector<unique_ptr<Connection>> connections;
  for (int i = 0; i < 8; ++i) connections.push_back(make_uniq<Connection>(f.db));
  f.fs->accesses = 0; std::atomic<int> errors {0}; std::vector<std::thread> threads;
  for (int i = 0; i < 8; ++i) threads.emplace_back([&, i] {
   try { BoilstreamSessionPublicationTestAccess::Publish(f.storage, *connections[i]->context,
       Pending("https://session" + std::to_string(i) + ".invalid/secrets")); }
   catch (...) { ++errors; }
  });
  for (auto &thread : threads) thread.join();
  Require(errors.load() == 0 && f.fs->accesses.load() == 0);
  for (int i = 0; i < 8; ++i) {
   auto state = f.storage.GetSessionForConnection(connections[i]->context->GetConnectionId());
   Require(state && state->GetEndpointUrl() == "https://session" + std::to_string(i) + ".invalid/secrets");
  }
 });
 test("failed_memory_resume_preserves_owned_session", [&] {
  Fixture f; auto state = Pending(argv[1]);
  BoilstreamSessionPublicationTestAccess::Publish(f.storage, *f.connection.context, state);
  f.fs->accesses = 0; RejectResume(f, *f.connection.context);
  Require(f.storage.GetSessionForConnection(f.connection.context->GetConnectionId()) == state);
  Require(state->IsSessionTokenValid() && state->refresh_token == vector<uint8_t>(32, 9));
  Require(state->GetEndpointUrl() == argv[1] && state->bootstrap_token_hash == "synthetic-bootstrap-identity");
 });
 return failed ? 1 : 0;
}
