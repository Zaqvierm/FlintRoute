package hardwarevalidation

import "testing"

func TestRouteCounterFromJSONSumsExactRouteRules(t *testing.T) {
	raw := []byte(`{"nftables":[
        {"rule":{"comment":"rp route=zapret action=queue","expr":[{"counter":{"packets":4,"bytes":10}}]}},
        {"rule":{"comment":"rp route=zapret action=other","expr":[{"counter":{"packets":3,"bytes":20}}]}},
        {"rule":{"comment":"rp route=zapret-extra action=other","expr":[{"counter":{"packets":100,"bytes":20}}]}}
    ]}`)
	packets, err := routeCounterFromJSON(raw, "zapret")
	if err != nil || packets != 7 {
		t.Fatalf("unexpected route counter: packets=%d err=%v", packets, err)
	}
}

func TestRouteCounterFromJSONRejectsMissingRule(t *testing.T) {
	if _, err := routeCounterFromJSON([]byte(`{"nftables":[]}`), "direct"); err == nil {
		t.Fatal("missing route counter was accepted")
	}
}

func TestTransportPassedRequiresCounterAndExpectedOutcome(t *testing.T) {
	if transportPassed("tcp_80", TransportEvidence{CounterRequired: true, CounterDelta: 0, Connected: true}, nil) {
		t.Fatal("transport passed without a counter increment")
	}
	if !transportPassed("tcp_80", TransportEvidence{CounterRequired: true, CounterDelta: 1, Connected: true}, nil) {
		t.Fatal("connected TCP transport was rejected")
	}
	if !transportPassed("dns_udp_53", TransportEvidence{CounterRequired: true, CounterDelta: 1, BlockedExpected: true}, errFixture{}) {
		t.Fatal("blocked DNS transport was rejected")
	}
	if transportPassed("dns_udp_53", TransportEvidence{CounterRequired: true, CounterDelta: 1, BlockedExpected: true, ResponseReceived: true}, nil) {
		t.Fatal("DROP DNS transport passed after receiving a response")
	}
	if !transportPassed("udp_443", TransportEvidence{PacketWritten: true}, nil) {
		t.Fatal("VLESS UDP transport incorrectly required an nft output counter")
	}
}

func TestSOCKSUDPHeaderRoundTripOffset(t *testing.T) {
	header, err := socksUDPHeader("example.com:443")
	if err != nil {
		t.Fatal(err)
	}
	packet := append(header, []byte("payload")...)
	offset, err := socksUDPPayloadOffset(packet)
	if err != nil {
		t.Fatal(err)
	}
	if string(packet[offset:]) != "payload" {
		t.Fatalf("unexpected SOCKS UDP payload: %q", packet[offset:])
	}
}

type errFixture struct{}

func (errFixture) Error() string { return "fixture" }
