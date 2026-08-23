package main

import (
	"context"
	"errors"
	"log"
	"os"
	"strconv"

	"router-policy/internal/helper"
)

func main() {
	uidText := os.Getenv("ROUTER_POLICY_HELPER_PEER_UID")
	if uidText == "" {
		log.Fatal("ROUTER_POLICY_HELPER_PEER_UID must identify the non-root controller")
	}
	uid, err := strconv.Atoi(uidText)
	if err != nil || uid <= 0 {
		log.Fatal("invalid ROUTER_POLICY_HELPER_PEER_UID")
	}
	socket := os.Getenv("ROUTER_POLICY_HELPER_SOCKET")
	if socket == "" {
		socket = "/var/run/router-policy/helper.sock"
	}
	if socket != "/var/run/router-policy/helper.sock" {
		log.Fatal("ROUTER_POLICY_HELPER_SOCKET is not allowlisted")
	}
	adapterPath := os.Getenv("ROUTER_POLICY_ADAPTER_PATH")
	if adapterPath == "" {
		adapterPath = "/usr/lib/router-policy/openwrt/adapter.sh"
	}
	if adapterPath != "/usr/lib/router-policy/openwrt/adapter.sh" {
		log.Fatal("ROUTER_POLICY_ADAPTER_PATH is not allowlisted")
	}
	configPath := os.Getenv("ROUTER_POLICY_CONFIG_PATH")
	if configPath == "" {
		configPath = "/etc/router-policy/config/default.json"
	}
	if configPath != "/etc/router-policy/config/default.json" {
		log.Fatal("ROUTER_POLICY_CONFIG_PATH is not allowlisted")
	}
	initDir := os.Getenv("ROUTER_POLICY_INIT_DIR")
	if initDir == "" {
		initDir = "/etc/init.d"
	}
	if initDir != "/etc/init.d" {
		log.Fatal("ROUTER_POLICY_INIT_DIR is not allowlisted")
	}
	if err := helper.ServeUnix(context.Background(), helper.ServerOptions{
		SocketPath: socket,
		PeerUID:    uid,
		Executor:   helper.AdapterExecutor{AdapterPath: adapterPath, ConfigPath: configPath, InitDir: initDir},
	}); err != nil && !errors.Is(err, context.Canceled) {
		log.Fatal(err)
	}
}
