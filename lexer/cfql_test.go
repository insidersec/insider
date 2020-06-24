package lexer

import (
	"testing"
)

func TestLoadIaCRulesShouldPass(t *testing.T) {
	queries, err := LoadIaCRules()

	if err != nil {
		t.Fatal(err)
	}

	if len(queries) <= 0 {
		t.Fatal("Should have loaded some rules")
	}
}
