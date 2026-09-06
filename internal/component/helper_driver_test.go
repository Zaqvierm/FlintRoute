package component

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
)

func TestHelperDriverRejectsUnsafeSocketAndDirectPackageMutation(t *testing.T) {
	if _, err := NewHelperDriver(OpenWrtDriver{}, "/tmp/not-allowlisted.sock", t.TempDir(), t.TempDir()); err == nil {
		t.Fatal("unsafe helper socket was accepted")
	}
	driver, err := NewHelperDriver(OpenWrtDriver{}, filepath.Join(t.TempDir(), "helper.sock"), t.TempDir(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := driver.Install(context.Background(), Release{}, Asset{}, "", Record{}); err == nil || !strings.Contains(err.Error(), "reviewed installer") {
		t.Fatalf("direct component install was not fenced: %v", err)
	}
}
