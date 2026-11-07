package hcldir_test

import (
	"strings"
	"testing"

	"github.com/go-authn/directory/hcldir"
)

func TestQueryTimeoutIsCheckedWithoutANetwork(t *testing.T) {
	sqlBlock := func(qt string) hcldir.Block {
		return hcldir.Block{Kind: "sql", Driver: "sqlite", DSNFile: "/d", UsersQuery: "select 1", QueryTimeout: qt}
	}
	for _, qt := range []string{"", "0", "20s", "1m30s"} {
		if err := sqlBlock(qt).Check(); err != nil {
			t.Errorf("query_timeout %q refused: %v", qt, err)
		}
	}
	for _, qt := range []string{"soon", "-5s", "20"} {
		err := sqlBlock(qt).Check()
		if err == nil || !strings.Contains(err.Error(), "query_timeout") {
			t.Errorf("query_timeout %q: %v, want a refusal naming it", qt, err)
		}
	}
	err := hcldir.Block{Kind: "ldap", URL: "ldaps://h", QueryTimeout: "5s"}.Check()
	if err == nil || !strings.Contains(err.Error(), "query_timeout") {
		t.Errorf("an ldap block with query_timeout: %v, want it refused as belonging to a sql block", err)
	}
}
