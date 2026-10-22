//===----------------------------------------------------------------------===//
//                         DuckDB
//
// boilstream_grammar.cpp
//
//===----------------------------------------------------------------------===//

#include "boilstream_grammar.hpp"

#include "duckdb/main/client_config.hpp"
#include "duckdb/main/client_context.hpp"
#include "duckdb/main/config.hpp"
#include "duckdb/main/database.hpp"
#include "duckdb/parser/expression/constant_expression.hpp"
#include "duckdb/parser/grammar_extension.hpp"
#include "duckdb/parser/peg/compiled_grammar.hpp"
#include "duckdb/parser/peg/parsed_grammar.hpp"
#include "duckdb/parser/peg/transformer/peg_transformer.hpp"
#include "duckdb/parser/statement/pragma_statement.hpp"
#include "duckdb/planner/extension_callback.hpp"

namespace duckdb {

namespace {

//! Maps a matched grammar rule onto the PRAGMA it stands for, with the arity the PRAGMA accepts.
struct BoilstreamCommandSpec {
	const char *rule;
	const char *pragma;
	const char *usage;
	idx_t min_args;
	idx_t max_args;
};

constexpr BoilstreamCommandSpec COMMANDS[] = {
    {"BoilstreamLogin", "boilstream_login", "BOILSTREAM LOGIN 'url_with_email' 'password' 'mfa_code'", 3, 3},
    {"BoilstreamRegisterUser", "boilstream_register_user", "BOILSTREAM REGISTER USER 'url_with_email' 'password'",
     2, 2},
    {"BoilstreamVerifyMfa", "boilstream_verify_mfa", "BOILSTREAM VERIFY MFA 'totp_code'", 1, 1},
    {"BoilstreamBootstrapSession", "boilstream_bootstrap_session", "BOILSTREAM BOOTSTRAP SESSION 'url_with_token'",
     1, 1},
    {"BoilstreamHelp", "boilstream_help", "BOILSTREAM HELP", 0, 0},
    {"BoilstreamCreateDucklake", "boilstream_create_ducklake",
     "CREATE DUCKLAKE 'name' ['description' ['s3_bucket_name']]", 1, 3},
};

const BoilstreamCommandSpec &FindCommand(const ParseResult &rule) {
	for (auto &command : COMMANDS) {
		if (StringUtil::CIEquals(rule.Name(), command.rule)) {
			return command;
		}
	}
	throw InternalException("boilstream grammar: unknown rule '%s'", rule.Name());
}

ParseResult &GetChoice(ParseResult &parse_result) {
	return parse_result.Cast<ListParseResult>().Child<ChoiceParseResult>(0).GetResult();
}

unique_ptr<PragmaStatement> MakePragma(const BoilstreamCommandSpec &command, vector<string> args) {
	if (args.size() < command.min_args || args.size() > command.max_args) {
		throw ParserException("%s: expected %llu%s string argument(s), got %llu. Usage: %s", command.pragma,
		                      command.min_args, command.min_args == command.max_args ? "" : " or more",
		                      args.size(), command.usage);
	}
	auto result = make_uniq<PragmaStatement>();
	result->info->name = Identifier(command.pragma);
	for (auto &arg : args) {
		result->info->parameters.push_back(ConstantExpression::String(std::move(arg)));
	}
	return result;
}

// StringLiteral* parses as Optional(Repeat), StringLiteral+ as a bare Repeat.
vector<string> TransformStringArgs(PEGTransformer &transformer, ParseResult &args_result) {
	vector<string> args;
	auto repeat = &args_result;
	if (args_result.type == ParseResultType::OPTIONAL) {
		auto &optional = args_result.Cast<OptionalParseResult>();
		if (!optional.HasResult()) {
			return args;
		}
		repeat = &optional.GetResult();
	}
	for (auto &child : repeat->Cast<RepeatParseResult>().GetChildren()) {
		args.push_back(transformer.Transform<string>(child.get()));
	}
	return args;
}

// BoilstreamStatement <- BoilstreamCommand / BoilstreamCreateDucklake / BoilstreamAttachDucklake
arena_ptr<TransformResultValue> FinalizeBoilstreamStatement(PEGTransformer &transformer, ParseResult &parse_result) {
	auto &statement = GetChoice(parse_result);
	auto &list = statement.Cast<ListParseResult>();
	unique_ptr<PragmaStatement> result;
	if (StringUtil::CIEquals(statement.Name(), "BoilstreamCommand")) {
		// 'BOILSTREAM' BoilstreamVerb StringLiteral*
		auto &verb = GetChoice(list.GetChild(1));
		result = MakePragma(FindCommand(verb), TransformStringArgs(transformer, list.GetChild(2)));
	} else if (StringUtil::CIEquals(statement.Name(), "BoilstreamAttachDucklake")) {
		// 'ATTACH' 'DUCKLAKE' StringLiteral 'AS' ColId
		auto catalog_id = transformer.Transform<string>(list.GetChild(2));
		auto alias = transformer.Transform<Identifier>(list.GetChild(4));
		result = make_uniq<PragmaStatement>();
		result->info->name = Identifier("boilstream_attach_ducklake");
		result->info->parameters.push_back(ConstantExpression::String(std::move(catalog_id)));
		result->info->parameters.push_back(ConstantExpression::String(alias.GetIdentifierName()));
	} else {
		// 'CREATE' 'DUCKLAKE' StringLiteral+
		result = MakePragma(FindCommand(statement), TransformStringArgs(transformer, list.GetChild(2)));
	}
	return transformer.MakeResult<unique_ptr<SQLStatement>>(std::move(result));
}

arena_ptr<TransformProcess> StartBoilstreamStatement(PEGTransformer &transformer, ParseResult &parse_result) {
	return transformer.MakeProcess<FinalizeTransformProcess>(transformer, parse_result, FinalizeBoilstreamStatement);
}

class BoilstreamGrammar final : public GrammarExtension {
public:
	BoilstreamGrammar()
	    : GrammarExtension(BOILSTREAM_GRAMMAR_NAME,
	                       "BOILSTREAM LOGIN / REGISTER USER / VERIFY MFA / BOOTSTRAP SESSION / HELP, "
	                       "CREATE DUCKLAKE and ATTACH DUCKLAKE statements for the boilstream PRAGMAs") {
	}

	vector<GrammarChange> GetChanges() const override {
		vector<GrammarChange> changes;
		changes.push_back(GrammarChange::AddRule(
		    "BoilstreamStatement <- BoilstreamCommand / BoilstreamCreateDucklake / BoilstreamAttachDucklake",
		    StartBoilstreamStatement));
		changes.push_back(GrammarChange::AddRule("BoilstreamCommand <- 'BOILSTREAM' BoilstreamVerb StringLiteral*"));
		changes.push_back(GrammarChange::AddRule("BoilstreamVerb <- BoilstreamLogin / BoilstreamRegisterUser / "
		                                         "BoilstreamVerifyMfa / BoilstreamBootstrapSession / BoilstreamHelp"));
		changes.push_back(GrammarChange::AddRule("BoilstreamLogin <- 'LOGIN'"));
		changes.push_back(GrammarChange::AddRule("BoilstreamRegisterUser <- 'REGISTER' 'USER'"));
		changes.push_back(GrammarChange::AddRule("BoilstreamVerifyMfa <- 'VERIFY' 'MFA'"));
		changes.push_back(GrammarChange::AddRule("BoilstreamBootstrapSession <- 'BOOTSTRAP' 'SESSION'"));
		changes.push_back(GrammarChange::AddRule("BoilstreamHelp <- 'HELP'"));
		changes.push_back(GrammarChange::AddRule("BoilstreamCreateDucklake <- 'CREATE' 'DUCKLAKE' StringLiteral+"));
		changes.push_back(
		    GrammarChange::AddRule("BoilstreamAttachDucklake <- 'ATTACH' 'DUCKLAKE' StringLiteral 'AS' ColId"));
		// Ordered choice: tried before the built-in statements, falls through when the keywords don't match.
		changes.push_back(GrammarChange::PrependChoice("Statement", "BoilstreamStatement"));
		return changes;
	}
};

//! Activates the grammar for every new connection, so the statements work without
//! SET active_grammar_extensions. A connection that already selected grammar
//! extensions is left alone; SET/RESET active_grammar_extensions still override.
class BoilstreamGrammarActivator final : public ExtensionCallback {
public:
	void OnConnectionOpened(ClientContext &context) override {
		auto &config = ClientConfig::GetConfig(context);
		if (!config.active_grammar_extensions.empty()) {
			return;
		}
		vector<string> extensions {BOILSTREAM_GRAMMAR_NAME};
		config.cached_grammar = CompiledGrammar::Create(context, extensions);
		config.active_grammar_extensions = std::move(extensions);
	}
};

} // namespace

void RegisterBoilstreamGrammar(ExtensionLoader &loader) {
	auto &db = loader.GetDatabaseInstance();
	GrammarExtension::Register(db, make_shared_ptr<BoilstreamGrammar>());
	ExtensionCallback::Register(DBConfig::GetConfig(db), make_shared_ptr<BoilstreamGrammarActivator>());
}

} // namespace duckdb
