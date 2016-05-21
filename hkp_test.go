package hkp

import (
	"testing"
)

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
