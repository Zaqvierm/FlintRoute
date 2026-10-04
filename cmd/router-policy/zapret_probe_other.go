//go:build !linux

package main

import "errors"

func runZapretHTTPSProbe(string, string) error {
	return errors.New("quick HTTPS probe requires Linux credential isolation")
}
