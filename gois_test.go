package gois

import (
	"testing"
)

func TestWhoisWithTldXyz(t *testing.T) {
	domain := "yeda.xyz"
	whoisInfo, _ := Whois(domain)
	if !whoisInfo.Registered {
		t.Errorf("%v registered: %v; want: true", domain, whoisInfo.Registered)
	}
}
