package scan

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/webcyber/webcyber/internal/model"
)

func TestMobileDirectoryFindsManifestRisks(t *testing.T) {
	root := t.TempDir()
	manifest := `<manifest><application android:allowBackup="true" android:usesCleartextTraffic="true"><activity android:name=".Main" android:exported="true" /></application></manifest>`
	if err := os.WriteFile(filepath.Join(root, "AndroidManifest.xml"), []byte(manifest), 0o600); err != nil {
		t.Fatal(err)
	}
	report, err := NewDefault().Scan(context.Background(), Config{Type: model.ScanTypeMobile, Target: root, Profile: model.ProfileSafe})
	if err != nil {
		t.Fatal(err)
	}
	rules := map[string]bool{}
	for _, finding := range report.Findings {
		rules[finding.RuleID] = true
	}
	for _, rule := range []string{"mobile.android.backup-enabled", "mobile.android.cleartext", "mobile.android.unprotected-exported-component"} {
		if !rules[rule] {
			t.Errorf("missing %s", rule)
		}
	}
}
