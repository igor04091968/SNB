//go:build windows

package wts

import "testing"

func TestParseClientAddressIPv4(t *testing.T) {
	address := &wtsClientAddressInfo{
		AddressFamily: addressFamilyINET,
		Address:       [20]byte{0, 0, 192, 168, 10, 44},
	}

	if got := parseClientAddress(address); got != "192.168.10.44" {
		t.Fatalf("parseClientAddress() = %q, want 192.168.10.44", got)
	}
}

func TestIdleSeconds(t *testing.T) {
	if got := idleSeconds(10000000, 40000000); got != 3 {
		t.Fatalf("idleSeconds() = %d, want 3", got)
	}
}
