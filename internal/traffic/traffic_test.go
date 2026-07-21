package traffic

import (
	"strings"
	"testing"
)

func TestParseProcNetDev(t *testing.T) {
	fixture := `Inter-| Receive | Transmit
 face |bytes packets errs drop fifo frame compressed multicast|bytes packets errs drop fifo colls carrier compressed
  eth1: 1024 10 2 0 0 0 0 0 2048 20 3 0 0 0 0 0
    br-lan: 4096 40 0 0 0 0 0 0 8192 80 0 0 0 0 0 0
`
	interfaces, err := ParseProcNetDev(strings.NewReader(fixture))
	if err != nil {
		t.Fatal(err)
	}
	if len(interfaces) != 2 || interfaces[0].Name != "br-lan" || interfaces[1].RXErrors != 2 || interfaces[1].TXBytes != 2048 {
		t.Fatalf("unexpected counters: %+v", interfaces)
	}
}

func TestParseProcNetDevRejectsTruncatedCounters(t *testing.T) {
	if _, err := ParseProcNetDev(strings.NewReader("eth1: 1 2 3\n")); err == nil {
		t.Fatal("expected malformed counter row failure")
	}
}
