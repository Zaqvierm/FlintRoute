//go:build linux

package main

import (
	"errors"
	"net/netip"
	"os"
	"os/exec"
	"router-policy/internal/netpolicy"
	"router-policy/internal/tspu"
	"syscall"
)

// Fixed-purpose child: no shell/flags/path from the caller and no root HTTP.
// nfqws/nft setup is performed separately by the owned privileged runner.
func runZapretHTTPSProbe(domain, address string) error {
	command, err := zapretHTTPSProbeCommand(domain, address)
	if err != nil {
		return err
	}
	err = command.Run()
	// Preserve curl's timeout exit code for the typed attempt result.
	if exit, ok := err.(*exec.ExitError); ok {
		os.Exit(exit.ExitCode())
	}
	return err
}

func zapretHTTPSProbeCommand(domain, address string) (*exec.Cmd, error) {
	canonical, err := tspu.NormalizeDomain(domain)
	ip, ipErr := netip.ParseAddr(address)
	if err != nil || ipErr != nil || canonical != domain || !ip.Is4() || !netpolicy.PublicResolverAddr(ip) {
		return nil, errors.New("quick probe domain or pinned address is invalid")
	}
	command := exec.Command("/usr/bin/curl", "--silent", "--show-error", "--noproxy", "*", "--connect-timeout", "5", "--max-time", "12", "--output", "/dev/null", "--write-out", "%{http_code}|%{time_total}", "--resolve", domain+":443:"+ip.String(), "https://"+domain+"/")
	command.Env = []string{"PATH=/usr/bin:/bin", "HOME=/tmp"}
	command.Stdout = os.Stdout
	command.Stderr = os.Stderr
	command.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 65534, Gid: 65534, Groups: []uint32{}}}
	return command, nil
}
