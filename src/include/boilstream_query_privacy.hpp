#pragma once

#include "duckdb/parser/parser.hpp"
#include "duckdb/parser/statement/pragma_statement.hpp"
#include "duckdb/common/string_util.hpp"

namespace duckdb {
// This classifies diagnostics only. It never executes, changes or rejects SQL.
// Use DuckDB's own scanner/parser so strings, comments and quoted identifiers
// have the same meaning here as at execution. Unknown lexical tails are private.
inline bool BoilstreamPrivateQueryError(const string &query) {
	// Bound diagnostic work even when the original parser failed on a huge input.
	if (query.size() > 1024 * 1024)
		return true;
	bool complete = false;
	auto tokens = Parser::Tokenize(query, complete);
	if (!complete)
		return true;
	idx_t headers = 0;
	for (idx_t i = 0; i < tokens.size(); ++i) {
		const auto &token = tokens[i];
		// Runtime conversion/renderer errors can contain a result value even
		// though the query only contains its ID. Protect this table function too.
		idx_t next = i + 1;
		// The tokenizer splits U&"..." [UESCAPE 'x'] into U, &, the quoted name and the escape clause.
		bool unicode_name = token.type == SimplifiedTokenType::SIMPLIFIED_TOKEN_IDENTIFIER && i + 2 < tokens.size() &&
		                    StringUtil::CIEquals(query.substr(token.start, 1), "u") &&
		                    tokens[i + 1].start == token.start + 1 && query[tokens[i + 1].start] == '&' &&
		                    tokens[i + 2].start == token.start + 2 &&
		                    tokens[i + 2].type == SimplifiedTokenType::SIMPLIFIED_TOKEN_IDENTIFIER &&
		                    query[tokens[i + 2].start] == '"';
		if (unicode_name) {
			next = i + 3;
			if (next + 1 < tokens.size() && tokens[next].type == SimplifiedTokenType::SIMPLIFIED_TOKEN_IDENTIFIER &&
			    StringUtil::CIEquals(query.substr(tokens[next].start, 7), "uescape") &&
			    tokens[next + 1].type == SimplifiedTokenType::SIMPLIFIED_TOKEN_STRING_CONSTANT)
				next += 2;
		}
		while (next < tokens.size() && tokens[next].type == SimplifiedTokenType::SIMPLIFIED_TOKEN_COMMENT)
			++next;
		if (token.type == SimplifiedTokenType::SIMPLIFIED_TOKEN_IDENTIFIER && next < tokens.size() &&
		    tokens[next].type == SimplifiedTokenType::SIMPLIFIED_TOKEN_OPERATOR && query[tokens[next].start] == '(') {
			constexpr char result_name[] = "boilstream_auth_result";
			const auto name_start = token.start + (query[token.start] == '"' ? 1 : 0);
			// Unicode escaped identifiers must be decoded by the parser before comparison.
			if (unicode_name || StringUtil::CIEquals(query.substr(name_start, sizeof(result_name) - 1), result_name)) {
				if (++headers > 64)
					return true;
				const auto length = tokens[next].start - token.start;
				if (length > 4096)
					return true;
				auto header = Parser::GetBuiltinParser();
				header.ParseQuery("PRAGMA " + query.substr(token.start, length) + ";");
				if (header.statements.size() != 1 || header.statements[0]->type != StatementType::PRAGMA_STATEMENT)
					return true;
				if (StringUtil::CIEquals(header.statements[0]->Cast<PragmaStatement>().info->name.GetIdentifierName(),
				                         result_name))
					return true;
			}
		}
		if (token.type != SimplifiedTokenType::SIMPLIFIED_TOKEN_KEYWORD ||
		    !StringUtil::CIEquals(query.substr(token.start, 6), "pragma"))
			continue;
		if (++headers > 64)
			return true;
		idx_t end = query.size();
		for (idx_t j = i + 1; j < tokens.size(); ++j) {
			if (tokens[j].type != SimplifiedTokenType::SIMPLIFIED_TOKEN_OPERATOR)
				continue;
			const auto c = query[tokens[j].start];
			if (c == '(' || c == '=' || c == ';') {
				end = tokens[j].start;
				break;
			}
		}
		if (end - token.start > 4096)
			return true;
		// Parse only the bounded pragma header, ending before the argument
		// delimiter. Malformed headers remain bounded and fail closed.
		// No ClientContext/catalog is consulted.
		auto parser = Parser::GetBuiltinParser();
		parser.ParseQuery(query.substr(token.start, end - token.start) + ";");
		if (parser.statements.size() != 1 || parser.statements[0]->type != StatementType::PRAGMA_STATEMENT)
			return true;
		const auto name =
		    StringUtil::Lower(parser.statements[0]->Cast<PragmaStatement>().info->name.GetIdentifierName());
		if (name == "boilstream_login" || name == "boilstream_register_user" || name == "boilstream_verify_mfa" ||
		    name == "boilstream_bootstrap_session")
			return true;
	}
	return false;
}
} // namespace duckdb
