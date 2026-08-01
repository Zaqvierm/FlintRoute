package main

import (
	"context"
	"flag"
	"fmt"
	"net/netip"
	"os"
	"time"

	"router-policy/internal/managementproof"
)

func main() {
	stateDir := flag.String("state", "", "state directory")
	runtimeDir := flag.String("runtime", "", "runtime directory")
	bootIDPath := flag.String("boot-id", "", "boot ID fixture")
	transactionID := flag.String("transaction", "", "transaction ID")
	revisionID := flag.String("revision", "", "revision ID")
	flag.Parse()
	manager, err := managementproof.New(*stateDir, *runtimeDir, managementproof.Options{
		BootIDPath: *bootIDPath,
		AdminProbe: func(context.Context, string) bool { return true },
	})
	if err != nil {
		fail(err)
	}
	_, err = manager.Issue(context.Background(), managementproof.Binding{TransactionID: *transactionID, RevisionID: *revisionID}, managementproof.Observation{
		Mode: managementproof.ModeLAN, ClientIP: netip.MustParseAddr("192.0.2.10"), LocalIP: netip.MustParseAddr("192.0.2.93"),
		Interface: "br-lan", Subnet: netip.MustParsePrefix("192.0.2.0/24"),
		ControlPlaneURL: "http://192.0.2.93:8787/api/v1/health", AdminHTTPURL: "http://192.0.2.93/", AdminHTTPAvailable: false,
	}, 15*time.Minute)
	if err != nil {
		fail(err)
	}
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
