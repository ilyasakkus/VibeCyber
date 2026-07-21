package scan

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/webcyber/webcyber/internal/model"
)

func TestSourceScanRedactsSecretsAndFindsElectronRisk(t *testing.T) {
	root := t.TempDir()
	secret := "AKIAIOSFODNN7EXAMPLE"
	content := "const access = \"" + secret + "\";\nconst win = new BrowserWindow({webPreferences: {nodeIntegration: true, contextIsolation: false}});\n"
	if err := os.WriteFile(filepath.Join(root, "main.js"), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "package.json"), []byte(`{"dependencies":{"left-pad":"latest","safe":"1.2.3"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	report, err := NewDefault().Scan(context.Background(), Config{Type: model.ScanTypeSource, Target: root, Profile: model.ProfileSafe})
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), secret) {
		t.Fatal("report leaked the secret value")
	}
	rules := make(map[string]bool)
	for _, finding := range report.Findings {
		rules[finding.RuleID] = true
	}
	for _, required := range []string{"source.secret.aws-access-key", "source.electron.node-integration", "source.electron.context-isolation", "source.dependency.unbounded-specification"} {
		if !rules[required] {
			t.Errorf("missing rule %s", required)
		}
	}
}

func TestLikelyPlaceholderAndEntropy(t *testing.T) {
	if !likelyPlaceholder("CHANGE_ME_NOW") {
		t.Fatal("expected placeholder")
	}
	if entropy("aB3$kL9z") <= entropy("aaaaaaaa") {
		t.Fatal("entropy ordering is unexpected")
	}
}
