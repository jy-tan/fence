package main

import (
	"strings"
	"testing"

	"github.com/Use-Tusk/fence/internal/sandbox"
)

func TestParseExposePortFlag(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want sandbox.ExposedPort
	}{
		{
			name: "bare port defaults to loopback",
			in:   "3000",
			want: sandbox.ExposedPort{BindAddress: "127.0.0.1", Port: 3000},
		},
		{
			name: "explicit loopback",
			in:   "127.0.0.1:8080",
			want: sandbox.ExposedPort{BindAddress: "127.0.0.1", Port: 8080},
		},
		{
			name: "all interfaces opt-in",
			in:   "0.0.0.0:8080",
			want: sandbox.ExposedPort{BindAddress: "0.0.0.0", Port: 8080},
		},
		{
			name: "specific LAN interface",
			in:   "192.168.1.10:8080",
			want: sandbox.ExposedPort{BindAddress: "192.168.1.10", Port: 8080},
		},
		{
			name: "ipv6 loopback",
			in:   "[::1]:8080",
			want: sandbox.ExposedPort{BindAddress: "::1", Port: 8080},
		},
		{
			name: "ipv6 wildcard",
			in:   "[::]:8080",
			want: sandbox.ExposedPort{BindAddress: "::", Port: 8080},
		},
		{
			name: "whitespace tolerated",
			in:   "  4096  ",
			want: sandbox.ExposedPort{BindAddress: "127.0.0.1", Port: 4096},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseExposePortFlag(tc.in)
			if err != nil {
				t.Fatalf("parseExposePortFlag(%q) returned error: %v", tc.in, err)
			}
			if got != tc.want {
				t.Errorf("parseExposePortFlag(%q) = %+v, want %+v", tc.in, got, tc.want)
			}
		})
	}
}

func TestParseExposePortFlag_Errors(t *testing.T) {
	cases := []struct {
		name        string
		in          string
		wantErrSubs []string
	}{
		{
			name:        "empty",
			in:          "",
			wantErrSubs: []string{"empty value"},
		},
		{
			name:        "non-numeric port",
			in:          "abc",
			wantErrSubs: []string{"invalid --port", "must be an integer"},
		},
		{
			name:        "port out of range",
			in:          "70000",
			wantErrSubs: []string{"invalid --port", "out of range"},
		},
		{
			name:        "zero port",
			in:          "0",
			wantErrSubs: []string{"invalid --port", "out of range"},
		},
		{
			name:        "negative port handled by SplitHostPort",
			in:          "-1",
			wantErrSubs: []string{"invalid --port"},
		},
		{
			name:        "missing bind address",
			in:          ":3000",
			wantErrSubs: []string{"invalid --port", "missing bind address"},
		},
		{
			name:        "non-IP bind address",
			in:          "localhost:3000",
			wantErrSubs: []string{"invalid --port", "must be a literal IP", "hostnames are not supported"},
		},
		{
			name:        "ipv6 without brackets gets misparsed",
			in:          "::1:3000",
			wantErrSubs: []string{"invalid --port"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseExposePortFlag(tc.in)
			if err == nil {
				t.Fatalf("parseExposePortFlag(%q) succeeded, want error", tc.in)
			}
			msg := err.Error()
			for _, sub := range tc.wantErrSubs {
				if !strings.Contains(msg, sub) {
					t.Errorf("parseExposePortFlag(%q) error %q does not contain %q", tc.in, msg, sub)
				}
			}
		})
	}
}

func TestParseExposePortFlags_PreservesOrderAndCombinations(t *testing.T) {
	in := []string{"3000", "0.0.0.0:8080", "[::1]:9090"}
	got, err := parseExposePortFlags(in)
	if err != nil {
		t.Fatalf("parseExposePortFlags(%v) error: %v", in, err)
	}
	want := []sandbox.ExposedPort{
		{BindAddress: "127.0.0.1", Port: 3000},
		{BindAddress: "0.0.0.0", Port: 8080},
		{BindAddress: "::1", Port: 9090},
	}
	if len(got) != len(want) {
		t.Fatalf("parseExposePortFlags returned %d entries, want %d (got=%+v)", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("entry %d: got %+v, want %+v", i, got[i], want[i])
		}
	}
}

func TestParseExposePortFlags_EmptyInputReturnsNil(t *testing.T) {
	got, err := parseExposePortFlags(nil)
	if err != nil {
		t.Fatalf("parseExposePortFlags(nil) error: %v", err)
	}
	if got != nil {
		t.Errorf("parseExposePortFlags(nil) = %v, want nil", got)
	}
}

func TestFormatExposureList(t *testing.T) {
	in := []sandbox.ExposedPort{
		{BindAddress: "127.0.0.1", Port: 3000},
		{BindAddress: "0.0.0.0", Port: 8080},
	}
	got := formatExposureList(in)
	want := "127.0.0.1:3000, 0.0.0.0:8080"
	if got != want {
		t.Errorf("formatExposureList = %q, want %q", got, want)
	}
}
