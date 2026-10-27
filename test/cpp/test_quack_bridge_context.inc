// Session ownership tests use the actual bridge registry and authentication
// scalar. The mock host owns opaque contexts; Rust permission tests are separate.
namespace {

int VerifyReplacementJwt(const char *, size_t, char *user, size_t user_size, char *bundle, size_t bundle_size) {
	return CopyOutput(user, user_size, "replacement-user") && CopyOutput(bundle, bundle_size, "replacement-authority")
	           ? 1
	           : 0;
}

bool Login(BridgeFixture &fixture, const char *sid) {
	auto result = fixture.connection.Query("SELECT boilstream_quack_authn('" + std::string(sid) + "', 'test-jwt', '')");
	if (result->HasError())
		throw std::runtime_error(result->GetError());
	return result->Collection().GetValue(0, 0).GetValue<bool>();
}

uint32_t QuotaRequester(const void *) { return 5001; }

TEST_CASE_METHOD(BridgeFixture, "Tenant quota survives reauthentication and retained context",
				 "[quack_bridge][quota]") {
	static const boilstream_quack_capability_context_factory_v2 factory{CreateContext, DestroyContext, QuotaRequester,
																		1};
	boilstream_quack_set_capability_context_factory_v2(&factory);
	struct Cleanup {
		~Cleanup() { boilstream_quack_catalog_session_close("quota-second"); }
	} cleanup;
	REQUIRE(Login(*this, SESSION_ID));
	auto retained = GetQuackSessionCtx(SESSION_ID);
	REQUIRE(retained->session_quota);
	REQUIRE(retained->session_quota->Tenant().Value() == 5001);
	REQUIRE(Login(*this, SESSION_ID));
	REQUIRE(GetQuackSessionCtx(SESSION_ID)->session_quota == retained->session_quota);
	REQUIRE_FALSE(Login(*this, "quota-second"));
	boilstream_quack_catalog_session_close(SESSION_ID);
	REQUIRE_FALSE(Login(*this, "quota-second"));
	retained.reset();
	REQUIRE(Login(*this, "quota-second"));
}

TEST_CASE_METHOD(BridgeFixture, "Repeated bridge callbacks retain one immutable authority", "[quack_bridge][context]") {
	const auto created = context_created.load();
	const auto destroyed = context_destroyed.load();
	auto first = GetQuackSessionCtx(SESSION_ID);
	REQUIRE(first);
	REQUIRE(first->user_id == "requester-17");
	const auto authority = first->capability_context.get();
	REQUIRE(authority);
	boilstream_quack_set_catalog_planner(&PlanSuccess);
	boilstream_quack_set_catalog_authorizer(&AuthorizeSuccess);
	for (size_t i = 0; i < 64; ++i) {
		auto next = GetQuackSessionCtx(SESSION_ID);
		REQUIRE(next.get() == first.get());
		REQUIRE(next->capability_context.get() == authority);
		PlanOutputs output;
		REQUIRE(output.Call() == 0);
		uint32_t owner = 0;
		char error[256] = {};
		REQUIRE(boilstream_quack_catalog_authorize(SESSION_ID, 2, CATALOG_ID, "", "", &owner, error, sizeof(error)) ==
		        0);
		REQUIRE(owner == 6001);
		REQUIRE(seen_capability == CAPABILITY);
		REQUIRE(seen_authorizer_capability == CAPABILITY);
	}
	REQUIRE(context_created.load() == created);
	REQUIRE(context_destroyed.load() == destroyed);
}

TEST_CASE_METHOD(BridgeFixture, "Close retires lookup but preserves an admitted authority lease",
                 "[quack_bridge][context]") {
	auto retained = GetQuackSessionCtx(SESSION_ID);
	REQUIRE(retained);
	const auto destroyed = context_destroyed.load();
	boilstream_quack_catalog_session_close(SESSION_ID);
	REQUIRE_FALSE(GetQuackSessionCtx(SESSION_ID));
	REQUIRE(context_destroyed.load() == destroyed);
	REQUIRE(*static_cast<const std::string *>(retained->capability_context.get()) == CAPABILITY);
	boilstream_quack_catalog_session_close(SESSION_ID);
	REQUIRE(context_destroyed.load() == destroyed);
	retained.reset();
	REQUIRE(context_destroyed.load() == destroyed + 1);
}

TEST_CASE_METHOD(BridgeFixture, "Replacement identity cannot change an already borrowed authority",
                 "[quack_bridge][context]") {
	auto old = GetQuackSessionCtx(SESSION_ID);
	const auto destroyed = context_destroyed.load();
	boilstream_quack_set_jwt_verifier(&VerifyReplacementJwt);
	REQUIRE(Login(*this, SESSION_ID));
	auto replacement = GetQuackSessionCtx(SESSION_ID);
	REQUIRE(replacement.get() != old.get());
	REQUIRE(replacement->user_id == "replacement-user");
	REQUIRE(*static_cast<const std::string *>(replacement->capability_context.get()) == "replacement-authority");
	REQUIRE(old->user_id == "requester-17");
	REQUIRE(*static_cast<const std::string *>(old->capability_context.get()) == CAPABILITY);
	REQUIRE(context_destroyed.load() == destroyed);
	old.reset();
	REQUIRE(context_destroyed.load() == destroyed + 1);
	// Destruction uses the factory captured at creation, not the current slot.
	boilstream_quack_set_capability_context_factory(nullptr);
	boilstream_quack_catalog_session_close(SESSION_ID);
	REQUIRE(context_destroyed.load() == destroyed + 1);
	replacement.reset();
	REQUIRE(context_destroyed.load() == destroyed + 2);
}

TEST_CASE_METHOD(BridgeFixture, "Context construction failure never publishes partial authority",
                 "[quack_bridge][context]") {
	auto old = GetQuackSessionCtx(SESSION_ID);
	const auto created = context_created.load();
	context_refused.store(true);
	REQUIRE_FALSE(Login(*this, "refused-context-session"));
	REQUIRE_FALSE(GetQuackSessionCtx("refused-context-session"));
	REQUIRE_FALSE(Login(*this, SESSION_ID));
	// Preserve the existing failed reauthentication policy. Quack owns closing
	// a connection whose policy revalidation fails; no new authority is installed.
	REQUIRE(GetQuackSessionCtx(SESSION_ID).get() == old.get());
	REQUIRE(context_created.load() == created);
	context_refused.store(false);
	boilstream_quack_set_capability_context_factory(nullptr);
	REQUIRE_FALSE(Login(*this, "no-factory-session"));
	REQUIRE_FALSE(GetQuackSessionCtx("no-factory-session"));
}

std::promise<void> *callback_entered = nullptr;
std::shared_future<void> callback_release;
std::atomic<bool> callback_authority_preserved {false};

int HoldAuthority(const void *context, uint32_t, const char *, const char *, const char *, uint32_t *owner, char *,
                  size_t) {
	auto expected = *static_cast<const std::string *>(context);
	callback_entered->set_value();
	callback_release.wait();
	callback_authority_preserved.store(*static_cast<const std::string *>(context) == expected);
	*owner = 6001;
	return 0;
}

TEST_CASE_METHOD(BridgeFixture, "Closing during a real authorizer callback does not free or rebind its context",
                 "[quack_bridge][context]") {
	std::promise<void> entered, release;
	callback_entered = &entered;
	callback_release = release.get_future().share();
	callback_authority_preserved.store(false);
	boilstream_quack_set_catalog_authorizer(&HoldAuthority);
	const auto destroyed = context_destroyed.load();
	auto worker = std::async(std::launch::async, [] {
		uint32_t owner = 0;
		char error[256] = {};
		auto rc = boilstream_quack_catalog_authorize(SESSION_ID, 2, CATALOG_ID, "", "", &owner, error, sizeof(error));
		return std::make_pair(rc, owner);
	});
	// Ensure exceptions in assertions still release and join the worker.
	struct ReleaseGuard {
		std::promise<void> &release;
		bool released = false;
		~ReleaseGuard() {
			if (!released)
				release.set_value();
		}
	} guard {release};
	REQUIRE(entered.get_future().wait_for(std::chrono::seconds(5)) == std::future_status::ready);
	boilstream_quack_catalog_session_close(SESSION_ID);
	REQUIRE_FALSE(GetQuackSessionCtx(SESSION_ID));
	REQUIRE(context_destroyed.load() == destroyed);
	boilstream_quack_set_jwt_verifier(&VerifyReplacementJwt);
	REQUIRE(Login(*this, SESSION_ID));
	REQUIRE(GetQuackSessionCtx(SESSION_ID)->user_id == "replacement-user");
	release.set_value();
	guard.released = true;
	REQUIRE(worker.wait_for(std::chrono::seconds(5)) == std::future_status::ready);
	const auto result = worker.get();
	REQUIRE(result.first == 0);
	REQUIRE(result.second == 6001);
	REQUIRE(callback_authority_preserved.load());
	REQUIRE(context_destroyed.load() == destroyed + 1);
	callback_entered = nullptr;
}

TEST_CASE_METHOD(BridgeFixture, "Concurrent session lookups retain one bounded context", "[quack_bridge][context]") {
	auto retained = GetQuackSessionCtx(SESSION_ID);
	const auto created = context_created.load();
	std::atomic<bool> valid {true};
	std::vector<std::thread> threads;
	for (size_t t = 0; t < 8; ++t) {
		threads.emplace_back([&] {
			for (size_t i = 0; i < 1024; ++i) {
				auto current = GetQuackSessionCtx(SESSION_ID);
				if (!current || current.get() != retained.get() ||
				    current->capability_context.get() != retained->capability_context.get())
					valid.store(false);
			}
		});
	}
	for (auto &thread : threads)
		thread.join();
	REQUIRE(valid.load());
	REQUIRE(context_created.load() == created);
}

const void *post_context_seen = nullptr;
int ObservePostContext(const void *context, uint32_t operation, const char *catalog, char *, size_t) {
	if (operation != 4 || std::string(catalog) != CATALOG_ID)
		return -1;
	post_context_seen = context;
	return *static_cast<const std::string *>(context) == CAPABILITY ? 0 : -1;
}

TEST_CASE_METHOD(BridgeFixture, "Post execute borrows the same context and denies a closed session",
                 "[quack_bridge][context]") {
	auto retained = GetQuackSessionCtx(SESSION_ID);
	boilstream_quack_set_post_execute_hook(&ObservePostContext);
	const auto created = context_created.load();
	char error[256] = {};
	for (size_t i = 0; i < 16; ++i) {
		post_context_seen = nullptr;
		REQUIRE(boilstream_quack_catalog_post_execute(SESSION_ID, 4, CATALOG_ID, error, sizeof(error)) == 0);
		REQUIRE(post_context_seen == retained->capability_context.get());
	}
	REQUIRE(context_created.load() == created);
	boilstream_quack_catalog_session_close(SESSION_ID);
	post_context_seen = nullptr;
	REQUIRE(boilstream_quack_catalog_post_execute(SESSION_ID, 4, CATALOG_ID, error, sizeof(error)) == -1);
	REQUIRE(post_context_seen == nullptr);
	REQUIRE(std::string(error) == "Quack session capability context is missing");
}

} // namespace
