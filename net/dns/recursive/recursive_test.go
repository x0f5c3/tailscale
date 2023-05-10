// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package recursive

import (
	"context"
	"testing"

	"tailscale.com/envknob"
)

func init() {
	envknob.Setenv("TS_DEBUG_RECURSIVE_DNS", "true")
}

func TestResolve(t *testing.T) {
	r := &Resolver{
		Logf: t.Logf,
	}
	ctx := context.Background()

	addrs, err := r.Resolve(ctx, "tailscale.com")
	if err != nil {
		t.Fatal(err)
	}

	t.Logf("addrs: %+v", addrs)
	if len(addrs) < 1 {
		t.Fatalf("expected at least one address")
	}

	var has4, has6 bool
	for _, addr := range addrs {
		has4 = has4 || addr.Is4()
		has6 = has6 || addr.Is6()
	}

	if !has4 {
		t.Errorf("expected at least one IPv4 address")
	}
	if !has6 {
		t.Errorf("expected at least one IPv6 address")
	}
}

func TestResolveNoIPv6(t *testing.T) {
	r := &Resolver{
		Logf:   t.Logf,
		NoIPv6: true,
	}
	ctx := context.Background()

	addrs, err := r.Resolve(ctx, "tailscale.com")
	if err != nil {
		t.Fatal(err)
	}

	t.Logf("addrs: %+v", addrs)
	if len(addrs) < 1 {
		t.Fatalf("expected at least one address")
	}

	for _, addr := range addrs {
		if addr.Is6() {
			t.Errorf("got unexpected IPv6 address: %v", addr)
		}
	}
}
