package hkp

import (
	"net/http"
	"net/url"
	"testing"
)

func TestNewClient(t *testing.T) {
	validKeyserver := &Keyserver{&url.URL{Scheme: "http", Host: "example.com", Path: ""}}
	tests := []struct {
		keyserver *Keyserver
		client    *http.Client
		panics    bool
	}{
		{nil, &http.Client{}, true},
		{&Keyserver{}, &http.Client{}, true},
		{validKeyserver, nil, false},
		{validKeyserver, &http.Client{}, false},
	}
	for i, test := range tests {
		if paniced := panics(func() { NewClient(test.keyserver, test.client) }); paniced != test.panics {
			t.Fatalf("test(%v): panic: expected=%v actual=%v", i, test.panics, paniced)
		}
	}

	expectedClient := &http.Client{}
	hkp := NewClient(validKeyserver, expectedClient)
	if hkp.client != expectedClient {
		t.Fatal("passed in client not present")
	}

	hkp = NewClient(validKeyserver, nil)
	if hkp.client == nil {
		t.Fatal("expected a non-nil client")
	}
}

func TestParseKeyserver(t *testing.T) {
	tests := []struct {
		url    string
		parsed string
		err    error
	}{
		{"ftp://example.com", "", UnsupportedSchemeError},
		{"example.com", "http://example.com:11371", nil},
		{"http://example.com/asdfasdf", "http://example.com", nil},
		{"http://example.com", "http://example.com", nil},
		{"https://example.com", "https://example.com", nil},
		{"https://example.com/asdfasdf", "https://example.com", nil},
		{"hkp://example.com", "http://example.com:11371", nil},
		{"hkp://example.com/asdfasd", "http://example.com:11371", nil},
		{"hkp://example.com:1234", "http://example.com:1234", nil},
		{"hkp://example.com:1234/asdfasd", "http://example.com:1234", nil},
		{"hkps://example.com", "https://example.com", nil},
		{"hkps://example.com/asdfads", "https://example.com", nil},
		{"hkps://example.com:1234", "https://example.com:1234", nil},
		{"hkps://example.com:1234/asdf", "https://example.com:1234", nil},
		{"https://[2001:cdba:0000:0000:0000:0000:3257:9652]", "https://[2001:cdba:0000:0000:0000:0000:3257:9652]", nil},
		{"http://[2001:cdba:0000:0000:0000:0000:3257:9652]/asdf", "http://[2001:cdba:0000:0000:0000:0000:3257:9652]", nil},
		{"hkp://[2001:cdba:0000:0000:0000:0000:3257:9652]/", "http://[2001:cdba:0000:0000:0000:0000:3257:9652]:11371", nil},
	}
	for _, test := range tests {
		parsed, err := ParseKeyserver(test.url)
		parsedURL := ""
		if err != test.err {
			t.Fatalf("url=%v err actual=%v expected=%v", test.url, err, test.err)
		}
		if parsed != nil {
			parsedURL = parsed.url.String()
		}
		if parsedURL != test.parsed {
			t.Fatalf("url=%v parsed actual=%v expected=%v", test.url, parsedURL, test.parsed)
		}
	}
}

func TestParseKeyID(t *testing.T) {
	tests := []struct {
		rawkeyid string
		err      error
	}{
		// length tests
		{"", UnsupportedKeyIDLength},                      // len = 0 => InvalidLength
		{"0", UnsupportedKeyIDLength},                     // len = 1 => InvalidLength
		{"0123456789A", UnsupportedKeyIDLength},           // len = 10 => InvalidLength
		{"01234567", nil},                                 // len = 8
		{"0123456701234567", nil},                         // len = 16
		{"01234567012345670123456701234567", nil},         // len = 32
		{"0123456701234567012345670123456701234567", nil}, // len = 40
		// hex tests
		{"01234567", nil},               // valid hex string, no leading 0x
		{"0x123456", InvalidKeyIDBytes}, // leading 0x, invalid
		{"not hex0", InvalidKeyIDBytes}, // nonhex string
	}
	for _, test := range tests {
		expectError := test.err != nil
		if _, err := ParseKeyID(test.rawkeyid); (err != nil) != expectError {
			t.Fatalf("test(%v): len(%v): error expected=%v actual=%v", test.rawkeyid, len(test.rawkeyid), expectError, err != nil)
		}
		if _, err := ParseKeyID(test.rawkeyid); err != nil && err != test.err {
			t.Fatalf("wrong error returned: expected=\"%v\" actual=\"%v\"", test.err.Error(), err.Error())
		}
	}

	keyID, err := ParseKeyID("BEEFBEEf")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if keyID.String() != "0xBEEFBEEf" {
		t.Fatalf("expected=0xBEEFBEEf actual=%v", keyID)
	}
}

func panics(f func()) (b bool) {
	defer func() {
		if p := recover(); p != nil {
			b = true
		}
	}()
	f()
	return
}
