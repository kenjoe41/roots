package main

import (
	"reflect"
	"testing"
)

func TestFilterLogURLs(t *testing.T) {
	all := []string{
		"https://ct.googleapis.com/logs/us1/argon2025h1/",
		"https://ct.googleapis.com/logs/eu1/xenon2025h1/",
		"https://yeti2025.ct.digicert.com/log/",
		"https://sabre2025h1.ct.sectigo.com/",
	}
	cases := []struct {
		name    string
		include string
		exclude string
		want    []string
	}{
		{
			name: "no filters is identity",
			want: all,
		},
		{
			name:    "include keeps only matching substrings",
			include: "googleapis",
			want: []string{
				"https://ct.googleapis.com/logs/us1/argon2025h1/",
				"https://ct.googleapis.com/logs/eu1/xenon2025h1/",
			},
		},
		{
			name:    "include matches any of several substrings",
			include: "digicert,sectigo",
			want: []string{
				"https://yeti2025.ct.digicert.com/log/",
				"https://sabre2025h1.ct.sectigo.com/",
			},
		},
		{
			name:    "exclude drops matching substrings",
			exclude: "googleapis",
			want: []string{
				"https://yeti2025.ct.digicert.com/log/",
				"https://sabre2025h1.ct.sectigo.com/",
			},
		},
		{
			name:    "include is applied before exclude, so exclude can carve out of an include set",
			include: "googleapis",
			exclude: "xenon",
			want: []string{
				"https://ct.googleapis.com/logs/us1/argon2025h1/",
			},
		},
		{
			name:    "a url matching both include and exclude is dropped (exclude wins)",
			include: "digicert",
			exclude: "digicert",
			want:    nil,
		},
		{
			name:    "include matching nothing yields empty",
			include: "no-such-log",
			want:    nil,
		},
		{
			name:    "whitespace around csv entries is trimmed",
			include: "  digicert , sectigo  ",
			want: []string{
				"https://yeti2025.ct.digicert.com/log/",
				"https://sabre2025h1.ct.sectigo.com/",
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := filterLogURLs(all, tc.include, tc.exclude)
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("filterLogURLs(include=%q, exclude=%q)\n got  %v\n want %v", tc.include, tc.exclude, got, tc.want)
			}
		})
	}
}
