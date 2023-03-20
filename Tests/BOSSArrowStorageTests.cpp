#include "../Source/BOSSArrowStorageEngine.hpp"
#define CATCH_CONFIG_MAIN
#include <ExpressionUtilities.hpp>
#include <catch2/catch.hpp>
using boss::utilities::operator""_;

TEST_CASE("Empty Table", "[empty]") {
  boss::engines::arrow_storage::Engine engine;

  auto result = engine.evaluate("CreateTable"_("DummyTable"_, "ColA"_, "ColB"_, "ColC"_));
  REQUIRE(result == boss::Expression(true));

  auto emptyResult = engine.evaluate("DummyTable"_);
  REQUIRE(emptyResult == "Table"_("Column"_("ColA"_, "List"_()), "Column"_("ColB"_, "List"_()),
                                  "Column"_("ColC"_, "List"_())));

  auto rewriteResult = engine.evaluate(
      "Select"_("Project"_("DummyTable"_, "As"_("ColA"_, "ColA"_, "ColB"_, "ColB"_)),
                "Greater"_("ColA"_, 10))); // NOLINT
  REQUIRE(rewriteResult == "Select"_("Project"_("Table"_("Column"_("ColA"_, "List"_()),
                                                         "Column"_("ColB"_, "List"_()),
                                                         "Column"_("ColC"_, "List"_())),
                                                "As"_("ColA"_, "ColA"_, "ColB"_, "ColB"_)),
                                     "Greater"_("ColA"_, 10)));
}

TEST_CASE("Create and Load TPCH's Nation", "[tpch]") {
  boss::engines::arrow_storage::Engine engine;

  auto createResult = engine.evaluate(
      "CreateTable"_("NATION"_, "N_NATIONKEY"_, "N_NAME"_, "N_REGIONKEY"_, "N_COMMENT"_));
  REQUIRE(createResult == boss::Expression(true));

  auto emptyResult = engine.evaluate("NATION"_);
  REQUIRE(emptyResult ==
          "Table"_("Column"_("N_NATIONKEY"_, "List"_()), "Column"_("N_NAME"_, "List"_()),
                   "Column"_("N_REGIONKEY"_, "List"_()), "Column"_("N_COMMENT"_, "List"_())));

  auto loadResult = engine.evaluate("Load"_("NATION"_, "../Tests/nation.tbl"));
  REQUIRE(loadResult == boss::Expression(true));

  auto loadedResult = engine.evaluate("NATION"_);

  auto result = std::move(loadedResult); // check if the spans can be moved
  REQUIRE(boss::get<boss::ComplexExpression>(result).getHead() == "Table"_);

  INFO(result);

  for(int i = 0; i < 4; ++i) {
    REQUIRE(boss::get<boss::ComplexExpression>(
                boss::get<boss::ComplexExpression>(result).getArguments()[i])
                .getHead() == "Column"_);
    REQUIRE(boss::get<boss::ComplexExpression>(
                boss::get<boss::ComplexExpression>(
                    boss::get<boss::ComplexExpression>(result).getArguments()[i])
                    .getArguments()[1])
                .getHead() == "List"_);
    REQUIRE(boss::get<boss::ComplexExpression>(
                boss::get<boss::ComplexExpression>(
                    boss::get<boss::ComplexExpression>(result).getArguments()[i])
                    .getArguments()[1])
                .getArguments()
                .size() > 1);
  }

  auto rewriteStrings = engine.evaluate("Select"_(
      "Project"_("NATION"_, "As"_("N_NAME"_, "N_NAME"_)), "StringContainsQ"_("N_NAME"_, "BRAZIL")));
  INFO(rewriteStrings);
  REQUIRE(boss::get<boss::ComplexExpression>(rewriteStrings).getDynamicArguments()[1] ==
          "Equal"_("N_NAME"_, 2));
}
