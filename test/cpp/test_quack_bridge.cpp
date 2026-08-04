//===----------------------------------------------------------------------===//
//                         DuckDB / Boilstream
//
// test_quack_bridge.cpp
//
// Exact C ABI and fail-closed tests for the trusted Quack planner bridge.
//===----------------------------------------------------------------------===//

#define CATCH_CONFIG_MAIN
#include <catch2/catch.hpp>

#include "duckdb/main/connection.hpp"
#include "duckdb/main/database.hpp"
#include "duckdb/main/extension_manager.hpp"
#include "quack_bridge.hpp"

#include <cstring>
#include <stdexcept>
#include <string>
#include <type_traits>

using namespace duckdb;

namespace {

using ExpectedPlannerAdapter = int (*)(const char *, const char *, const char *, uint32_t *, char *, size_t, char *,
                                       size_t, char *, size_t, char *, size_t);
static_assert(std::is_same<boilstream_quack_catalog_planner_fn, ExpectedPlannerAdapter>::value,
              "Boilstream host planner ABI changed");
static_assert(std::is_same<decltype(&boilstream_quack_catalog_plan), ExpectedPlannerAdapter>::value,
              "Quack planner adapter ABI changed");

constexpr const char *SESSION_ID = "bridge-test-session";
constexpr const char *CAPABILITY = "opaque-signed-capability";
constexpr const char *CATALOG_ID = "9a927d1b-30f5-48da-91eb-af1492bf31c0";
constexpr const char *EXECUTION_ALIAS = "__ducklake_metadata_9a927d1b_30f5_48da_91eb_af1492bf31c0__stream";
constexpr const char *SQL_IN = "INSERT INTO incoming VALUES (42)";
constexpr const char *SQL_OUT = "INSERT INTO __stream.incoming VALUES (42)";

int planner_result = 0;
const char *planner_execution_alias = EXECUTION_ALIAS;
bool planner_inputs_were_clear = false;
std::string seen_capability;
std::string seen_declared_catalog;
std::string seen_sql;

bool CopyOutput(char *out, size_t capacity, const char *value) {
	const auto length = std::strlen(value);
	if (!out || capacity <= length) {
		return false;
	}
	std::memcpy(out, value, length + 1);
	return true;
}

int VerifyJwt(const char *, size_t, char *user_id_out, size_t user_id_capacity, char *capability_out,
              size_t capability_capacity) {
	return CopyOutput(user_id_out, user_id_capacity, "requester-17") &&
	               CopyOutput(capability_out, capability_capacity, CAPABILITY)
	           ? 1
	           : 0;
}

int PlanSuccess(const char *capability, const char *declared_catalog_id, const char *sql_in, uint32_t *operation_out,
                char *catalog_id_out, size_t catalog_id_out_size, char *execution_catalog_alias_out,
                size_t execution_catalog_alias_out_size, char *sql_out_buf, size_t sql_out_size, char *error_out_buf,
                size_t error_out_size) {
	planner_inputs_were_clear = operation_out && *operation_out == 0 && catalog_id_out && catalog_id_out[0] == '\0' &&
	                            execution_catalog_alias_out && execution_catalog_alias_out[0] == '\0' && sql_out_buf &&
	                            sql_out_buf[0] == '\0' && error_out_buf && error_out_buf[0] == '\0';
	seen_capability = capability ? capability : "";
	seen_declared_catalog = declared_catalog_id ? declared_catalog_id : "";
	seen_sql = sql_in ? sql_in : "";
	if (!operation_out || !CopyOutput(catalog_id_out, catalog_id_out_size, CATALOG_ID) ||
	    !CopyOutput(execution_catalog_alias_out, execution_catalog_alias_out_size, planner_execution_alias) ||
	    !CopyOutput(sql_out_buf, sql_out_size, SQL_OUT)) {
		CopyOutput(error_out_buf, error_out_size, "test output buffer too small");
		return -1;
	}
	*operation_out = 4;
	return planner_result;
}

int PlanDenialWithDirtyOutputs(const char *, const char *, const char *, uint32_t *operation_out, char *catalog_id_out,
                               size_t catalog_id_out_size, char *execution_catalog_alias_out,
                               size_t execution_catalog_alias_out_size, char *sql_out_buf, size_t sql_out_size,
                               char *error_out_buf, size_t error_out_size) {
	*operation_out = 99;
	CopyOutput(catalog_id_out, catalog_id_out_size, "dirty-catalog");
	CopyOutput(execution_catalog_alias_out, execution_catalog_alias_out_size, "dirty-alias");
	CopyOutput(sql_out_buf, sql_out_size, "dirty-sql");
	CopyOutput(error_out_buf, error_out_size, "planner denied exactly");
	return -7;
}

int PlanInvalidStatus(const char *, const char *, const char *, uint32_t *operation_out, char *catalog_id_out,
                      size_t catalog_id_out_size, char *execution_catalog_alias_out,
                      size_t execution_catalog_alias_out_size, char *sql_out_buf, size_t sql_out_size, char *, size_t) {
	*operation_out = 99;
	CopyOutput(catalog_id_out, catalog_id_out_size, "dirty-catalog");
	CopyOutput(execution_catalog_alias_out, execution_catalog_alias_out_size, "dirty-alias");
	CopyOutput(sql_out_buf, sql_out_size, "dirty-sql");
	return 2;
}

int PlanThrows(const char *, const char *, const char *, uint32_t *operation_out, char *catalog_id_out,
               size_t catalog_id_out_size, char *execution_catalog_alias_out, size_t execution_catalog_alias_out_size,
               char *sql_out_buf, size_t sql_out_size, char *, size_t) {
	*operation_out = 99;
	CopyOutput(catalog_id_out, catalog_id_out_size, "dirty-catalog");
	CopyOutput(execution_catalog_alias_out, execution_catalog_alias_out_size, "dirty-alias");
	CopyOutput(sql_out_buf, sql_out_size, "dirty-sql");
	throw std::runtime_error("planner exception must not cross C ABI");
}

struct PlanOutputs {
	uint32_t operation = 99;
	char catalog[128] = "stale-catalog";
	char alias[192] = "stale-alias";
	char sql[256] = "stale-sql";
	char error[128] = "stale-error";

	int Call() {
		return boilstream_quack_catalog_plan(SESSION_ID, CATALOG_ID, SQL_IN, &operation, catalog, sizeof(catalog),
		                                     alias, sizeof(alias), sql, sizeof(sql), error, sizeof(error));
	}

	void RequireDataCleared() const {
		REQUIRE(operation == 0);
		REQUIRE(catalog[0] == '\0');
		REQUIRE(alias[0] == '\0');
		REQUIRE(sql[0] == '\0');
	}
};

struct BridgeFixture {
	DuckDB db {nullptr};
	Connection connection {db};

	BridgeFixture() {
		ExtensionInfo extension_info {};
		ExtensionActiveLoad load_info {*db.instance, extension_info, "boilstream_bridge_test"};
		ExtensionLoader loader {load_info};
		RegisterQuackBridge(loader);
		planner_execution_alias = EXECUTION_ALIAS;
		boilstream_quack_set_jwt_verifier(&VerifyJwt);
		boilstream_quack_set_catalog_planner(nullptr);
		auto result =
		    connection.Query("SELECT boilstream_quack_authn('" + std::string(SESSION_ID) + "', 'test-jwt', '')");
		const auto query_error = result->HasError() ? result->GetError() : "";
		INFO(query_error);
		REQUIRE(!result->HasError());
		REQUIRE(result->GetValue(0, 0).GetValue<bool>());
	}

	~BridgeFixture() {
		boilstream_quack_catalog_session_close(SESSION_ID);
		boilstream_quack_set_catalog_planner(nullptr);
		boilstream_quack_set_jwt_verifier(nullptr);
	}
};

} // namespace

TEST_CASE_METHOD(BridgeFixture, "Planner bridge forwards opaque execution alias independently of rewrite",
                 "[quack][bridge][abi]") {
	boilstream_quack_set_catalog_planner(&PlanSuccess);

	for (const auto result_code : {0, 1}) {
		planner_result = result_code;
		planner_inputs_were_clear = false;
		PlanOutputs outputs;

		REQUIRE(outputs.Call() == result_code);
		REQUIRE(planner_inputs_were_clear);
		REQUIRE(seen_capability == CAPABILITY);
		REQUIRE(seen_declared_catalog == CATALOG_ID);
		REQUIRE(seen_sql == SQL_IN);
		REQUIRE(outputs.operation == 4);
		REQUIRE(std::string(outputs.catalog) == CATALOG_ID);
		REQUIRE(std::string(outputs.alias) == EXECUTION_ALIAS);
		REQUIRE(std::string(outputs.sql) == SQL_OUT);
		REQUIRE(outputs.error[0] == '\0');
	}
}

TEST_CASE_METHOD(BridgeFixture, "Planner bridge preserves an empty execution target", "[quack][bridge][abi]") {
	boilstream_quack_set_catalog_planner(&PlanSuccess);
	planner_result = 0;
	planner_execution_alias = "";
	PlanOutputs outputs;

	REQUIRE(outputs.Call() == 0);
	REQUIRE(outputs.operation == 4);
	REQUIRE(std::string(outputs.catalog) == CATALOG_ID);
	REQUIRE(outputs.alias[0] == '\0');
	REQUIRE(outputs.error[0] == '\0');
}

TEST_CASE_METHOD(BridgeFixture, "Planner bridge clears outputs on denial and invalid status",
                 "[quack][bridge][failure]") {
	SECTION("planner denial preserves its diagnostic only") {
		boilstream_quack_set_catalog_planner(&PlanDenialWithDirtyOutputs);
		PlanOutputs outputs;
		REQUIRE(outputs.Call() == -7);
		outputs.RequireDataCleared();
		REQUIRE(std::string(outputs.error) == "planner denied exactly");
	}

	SECTION("unexpected positive status fails closed") {
		boilstream_quack_set_catalog_planner(&PlanInvalidStatus);
		PlanOutputs outputs;
		REQUIRE(outputs.Call() == -1);
		outputs.RequireDataCleared();
		REQUIRE(std::string(outputs.error) == "Catalog planner returned invalid status");
	}

	SECTION("planner-detected execution alias truncation fails closed") {
		boilstream_quack_set_catalog_planner(&PlanSuccess);
		PlanOutputs outputs;
		REQUIRE(boilstream_quack_catalog_plan(SESSION_ID, CATALOG_ID, SQL_IN, &outputs.operation, outputs.catalog,
		                                      sizeof(outputs.catalog), outputs.alias, 8, outputs.sql,
		                                      sizeof(outputs.sql), outputs.error, sizeof(outputs.error)) == -1);
		REQUIRE(outputs.operation == 0);
		REQUIRE(outputs.catalog[0] == '\0');
		REQUIRE(outputs.alias[0] == '\0');
		REQUIRE(outputs.sql[0] == '\0');
		REQUIRE(std::string(outputs.error) == "test output buffer too small");
	}
}

TEST_CASE_METHOD(BridgeFixture, "Planner bridge contains exceptions and clears outputs", "[quack][bridge][failure]") {
	boilstream_quack_set_catalog_planner(&PlanThrows);
	PlanOutputs outputs;
	int rc = 0;
	REQUIRE_NOTHROW(rc = outputs.Call());
	REQUIRE(rc == -1);
	outputs.RequireDataCleared();
	REQUIRE(std::string(outputs.error) == "Catalog planner bridge failed");
}

TEST_CASE_METHOD(BridgeFixture, "Planner bridge rejects invalid output buffers before callback",
                 "[quack][bridge][failure]") {
	boilstream_quack_set_catalog_planner(&PlanSuccess);

	enum class InvalidOutput {
		OPERATION_POINTER,
		CATALOG_POINTER,
		CATALOG_CAPACITY,
		ALIAS_POINTER,
		ALIAS_CAPACITY,
		SQL_POINTER,
		SQL_CAPACITY,
		ERROR_POINTER,
		ERROR_CAPACITY,
	};
	const InvalidOutput cases[] = {
	    InvalidOutput::OPERATION_POINTER, InvalidOutput::CATALOG_POINTER, InvalidOutput::CATALOG_CAPACITY,
	    InvalidOutput::ALIAS_POINTER,     InvalidOutput::ALIAS_CAPACITY,  InvalidOutput::SQL_POINTER,
	    InvalidOutput::SQL_CAPACITY,      InvalidOutput::ERROR_POINTER,   InvalidOutput::ERROR_CAPACITY,
	};

	for (const auto invalid : cases) {
		PlanOutputs outputs;
		auto operation_out = &outputs.operation;
		auto catalog_out = outputs.catalog;
		auto catalog_capacity = sizeof(outputs.catalog);
		auto alias_out = outputs.alias;
		auto alias_capacity = sizeof(outputs.alias);
		auto sql_out = outputs.sql;
		auto sql_capacity = sizeof(outputs.sql);
		auto error_out = outputs.error;
		auto error_capacity = sizeof(outputs.error);

		switch (invalid) {
		case InvalidOutput::OPERATION_POINTER:
			operation_out = nullptr;
			break;
		case InvalidOutput::CATALOG_POINTER:
			catalog_out = nullptr;
			break;
		case InvalidOutput::CATALOG_CAPACITY:
			catalog_capacity = 0;
			break;
		case InvalidOutput::ALIAS_POINTER:
			alias_out = nullptr;
			break;
		case InvalidOutput::ALIAS_CAPACITY:
			alias_capacity = 0;
			break;
		case InvalidOutput::SQL_POINTER:
			sql_out = nullptr;
			break;
		case InvalidOutput::SQL_CAPACITY:
			sql_capacity = 0;
			break;
		case InvalidOutput::ERROR_POINTER:
			error_out = nullptr;
			break;
		case InvalidOutput::ERROR_CAPACITY:
			error_capacity = 0;
			break;
		}

		INFO("invalid output case " << static_cast<int>(invalid));
		REQUIRE(boilstream_quack_catalog_plan(SESSION_ID, CATALOG_ID, SQL_IN, operation_out, catalog_out,
		                                      catalog_capacity, alias_out, alias_capacity, sql_out, sql_capacity,
		                                      error_out, error_capacity) == -1);
		if (operation_out) {
			REQUIRE(outputs.operation == 0);
		}
		if (catalog_out && catalog_capacity > 0) {
			REQUIRE(outputs.catalog[0] == '\0');
		}
		if (alias_out && alias_capacity > 0) {
			REQUIRE(outputs.alias[0] == '\0');
		}
		if (sql_out && sql_capacity > 0) {
			REQUIRE(outputs.sql[0] == '\0');
		}
		if (error_out && error_capacity > 0) {
			REQUIRE(std::string(outputs.error) == "Catalog planner received invalid buffers");
		}
	}
}

TEST_CASE_METHOD(BridgeFixture, "Planner bridge rejects null input strings with cleared outputs",
                 "[quack][bridge][failure]") {
	boilstream_quack_set_catalog_planner(&PlanSuccess);
	for (size_t null_index = 0; null_index < 3; ++null_index) {
		PlanOutputs outputs;
		const char *session_id = null_index == 0 ? nullptr : SESSION_ID;
		const char *catalog_id = null_index == 1 ? nullptr : CATALOG_ID;
		const char *sql_in = null_index == 2 ? nullptr : SQL_IN;
		INFO("null input index " << null_index);
		REQUIRE(boilstream_quack_catalog_plan(session_id, catalog_id, sql_in, &outputs.operation, outputs.catalog,
		                                      sizeof(outputs.catalog), outputs.alias, sizeof(outputs.alias),
		                                      outputs.sql, sizeof(outputs.sql), outputs.error,
		                                      sizeof(outputs.error)) == -1);
		outputs.RequireDataCleared();
		REQUIRE(std::string(outputs.error) == "Catalog planner received invalid buffers");
	}
}

TEST_CASE_METHOD(BridgeFixture, "Planner bridge fails closed without planner or session", "[quack][bridge][failure]") {
	SECTION("planner missing") {
		PlanOutputs outputs;
		REQUIRE(outputs.Call() == -1);
		outputs.RequireDataCleared();
		REQUIRE(std::string(outputs.error) == "Catalog planner is not registered");
	}

	SECTION("session missing") {
		boilstream_quack_set_catalog_planner(&PlanSuccess);
		boilstream_quack_catalog_session_close(SESSION_ID);
		PlanOutputs outputs;
		REQUIRE(outputs.Call() == -1);
		outputs.RequireDataCleared();
		REQUIRE(std::string(outputs.error) == "Quack session capability bundle is missing");
	}
}
