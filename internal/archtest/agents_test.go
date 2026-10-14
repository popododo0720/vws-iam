package archtest

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ruleTable parses the '| Rule | Enforcer |' table under '## Rules' and
// returns the enforcer cell of every row.
func ruleTable(md string) ([]string, error) {
	var rows []string
	on, header := false, false
	for _, line := range strings.Split(md, "\n") {
		line = strings.TrimSpace(line)
		switch {
		case line == "## Rules":
			on = true
			continue
		case on && strings.HasPrefix(line, "## "):
			on = false
		}
		if !on || !strings.HasPrefix(line, "|") {
			continue
		}
		cells := strings.Split(strings.Trim(line, "|"), "|")
		if !header {
			if len(cells) != 2 || strings.TrimSpace(cells[0]) != "Rule" || strings.TrimSpace(cells[1]) != "Enforcer" {
				return nil, fmt.Errorf("'## Rules' needs a '| Rule | Enforcer |' table, got %q", line)
			}
			header = true
			continue
		}
		if strings.Trim(line, "|-: ") == "" {
			continue // separator row
		}
		rows = append(rows, strings.TrimSpace(cells[len(cells)-1]))
	}
	if !header {
		return nil, fmt.Errorf("no '## Rules' table")
	}
	if len(rows) == 0 {
		return nil, fmt.Errorf("the rule table is empty")
	}
	return rows, nil
}

func checkEnforcers(md string) (judgment, total int, err error) {
	rows, err := ruleTable(md)
	if err != nil {
		return 0, 0, err
	}
	for i, e := range rows {
		switch e {
		case "":
			return 0, 0, fmt.Errorf("rule row %d names no enforcer; write a test, lint or CI step, or 'Judgment'", i+1)
		case "Judgment":
			judgment++
		}
	}
	return judgment, len(rows), nil
}

func TestAgentsRulesNameAnEnforcer(t *testing.T) {
	b, err := os.ReadFile(filepath.Join(repoRoot(t), "AGENTS.md"))
	if err != nil {
		t.Fatal(err)
	}
	j, n, err := checkEnforcers(string(b))
	if err != nil {
		t.Fatalf("AGENTS.md: %v", err)
	}
	t.Logf("judgment: %d of %d rules are Judgment (no automated enforcer)", j, n)
}

func TestEnforcerCheckCatchesViolations(t *testing.T) {
	good := "# t\n## Rules\n\n| Rule | Enforcer |\n| --- | --- |\n| a | `TestA` |\n| b | Judgment |\n\n## next\n| x | |\n"
	if j, n, err := checkEnforcers(good); err != nil || j != 1 || n != 2 {
		t.Fatalf("good table: judgment=%d total=%d err=%v, want 1 of 2", j, n, err)
	}
	for name, md := range map[string]string{
		"empty enforcer": strings.Replace(good, "| b | Judgment |", "| b |  |", 1),
		"wrong header":   strings.Replace(good, "| Rule | Enforcer |", "| Rule | Enforced by |", 1),
		"no table":       "# t\n## Other\n",
		"no rows":        "## Rules\n| Rule | Enforcer |\n| --- | --- |\n",
	} {
		if _, _, err := checkEnforcers(md); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
