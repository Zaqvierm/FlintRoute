//go:build linux

package main

import (
	"strings"
	"testing"
)

func TestQuickHTTPSChildDropsPrivilegeAndPinsPath(t *testing.T) {
	command, err := zapretHTTPSProbeCommand("youtube.com", "8.8.8.8")
	if err != nil {
		t.Fatal(err)
	}
	credential := command.SysProcAttr.Credential
	if credential == nil || credential.Uid != 65534 || credential.Gid != 65534 || len(credential.Groups) != 0 {
		t.Fatal("probe HTTP retains privilege")
	}
	args := strings.Join(command.Args, " ")
	if command.Path != "/usr/bin/curl" || !strings.Contains(args, "--resolve youtube.com:443:8.8.8.8") || !strings.Contains(args, "https://youtube.com/") || strings.Contains(args, "--insecure") {
		t.Fatal("unpinned or unsafe probe command")
	}
	for _, tc := range [][2]string{{"youtube.com;id", "8.8.8.8"}, {"youtube.com", "127.0.0.1"}, {"youtube.com", "192.168.0.1"}, {"youtube.com", "169.254.1.1"}, {"youtube.com", "::1"}} {
		if _, err := zapretHTTPSProbeCommand(tc[0], tc[1]); err == nil {
			t.Fatal("hostile or private probe accepted")
		}
	}
}
