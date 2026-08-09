package api

import (
	"net/http/httptest"
	"testing"
)

func TestRequestHostAcceptsRouterAddressAndRejectsLoopbackOrInjection(t *testing.T) {
	tests := []struct {
		host string
		want string
	}{
		{"192.0.2.1:8787", "192.0.2.1"},
		{"[2001:db8::1]:8787", "2001:db8::1"},
		{"router.example:8787", "router.example"},
		{"127.0.0.1:8787", ""},
		{"localhost:8787", ""},
		{"router.example;reboot", ""},
	}
	for _, test := range tests {
		request := httptest.NewRequest("GET", "http://example.test/api/v1/tgws", nil)
		request.Host = test.host
		if got := requestHost(request); got != test.want {
			t.Fatalf("requestHost(%q)=%q want %q", test.host, got, test.want)
		}
	}
}
