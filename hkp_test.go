package hkp

import (
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
	"golang.org/x/net/context"
)

// TODO: Add MultiKeyServer Test
// TODO: Add Incorrect Content-Type Test
// TODO: Add Key Not Found Test
// TODO: Add Test for Returned Key's KeyID matches Search KeyID
// TODO: Add Test for Empty client in GetKeysByIDs

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
	if hkp.keyserver != validKeyserver {
		t.Fatal("passed in keyserver not present")
	}
}

func TestGetKeysByID_DebianKey_ReturnsEntity(t *testing.T) {
	debianJessieArchiveSigningKey := "126C0D24BD8A2942CC7DF8AC7638D0442B90D010"
	ubuntuKeyServer := "keyserver.ubuntu.com"
	ks, err := ParseKeyserver(ubuntuKeyServer)
	if err != nil {
		t.Fatalf("error parsing keyserver: %v", err)
	}
	keyID, err := ParseKeyID(debianJessieArchiveSigningKey)
	if err != nil {
		t.Fatalf("error parsing keyID: %v", err)
	}
	client := NewClient(ks, nil)
	el, err := client.GetKeysByID(context.TODO(), keyID)
	if err != nil {
		t.Fatalf("error getting key: %v", err)
	}
	if len(el) != 1 {
		t.Fatal("failed to get key")
	}
}

func TestGetKeysByID_NilContext_Panics(t *testing.T) {
	client := &Client{client: &http.Client{}}
	validID := &KeyID{key: "01234567"}
	if p := panics(func() { client.GetKeysByID(nil, validID) }); !p {
		t.Fatal("expected panic on nil context")
	}
}

func TestGetKeysByID_NilKeyID_Panics(t *testing.T) {
	client := &Client{client: &http.Client{}}
	validContext := context.TODO()
	if p := panics(func() { client.GetKeysByID(validContext, nil) }); !p {
		t.Fatal("expected panic on nil keyID")
	}
}

func TestGetKeyByID_ValidKeySingleKey_ReturnsSingleKey(t *testing.T) {
	server := newSingleKeyServer()
	defer server.Close()
	keyserver, err := ParseKeyserver(server.URL)
	if err != nil {
		t.Fatalf("error parsing test server url: %v", err)
	}
	if keyserver == nil {
		t.Fatal("could not parse test server url")
	}
	client := NewClient(keyserver, nil)
	if client == nil {
		t.Fatal("could not create new client")
	}

	keyID, err := ParseKeyID(server.entities[0].PrimaryKey.KeyIdString())
	if err != nil {
		t.Fatalf("could not parse keyID string from entitiy: %v", err)
	}

	entities, err := client.GetKeysByID(context.TODO(), keyID)
	if err != nil {
		t.Fatalf("unexpected error retrieving entities: %v", err)
	}
	if len(entities) != 1 {
		t.Fatalf("len(entities) expected=%v actual=%v", 1, len(entities))
	}
	if expected, actual := server.entities[0].PrimaryKey.KeyIdString(), entities[0].PrimaryKey.KeyIdString(); expected != actual {
		t.Fatalf("keyID mismatch: expected=%v actual=%v", expected, actual)
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

type testServer struct {
	*httptest.Server
	entities openpgp.EntityList
	// keyIds                   []string
	search                   string
	searchValuePresentCount  int
	op                       string
	opValuePresentCount      int
	options                  string
	optionsValuePresentCount int
	sendInvalidContentType   bool
}

func (ts *testServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	v := r.URL.Query()
	if search, ok := v["search"]; ok {
		ts.searchValuePresentCount = len(search)
		ts.search = search[0]
	}
	if op, ok := v["op"]; ok {
		ts.opValuePresentCount = len(op)
		ts.op = op[0]
	}
	if options, ok := v["options"]; ok {
		ts.optionsValuePresentCount = len(options)
		ts.options = options[0]
	}
	if ts.sendInvalidContentType {
		w.Header().Set("Content-Type", "text/html")
	} else {
		w.Header().Set("Content-Type", "application/pgp-keys")
	}
	if len(ts.entities) == 0 {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	w.WriteHeader(http.StatusOK)
	for _, e := range ts.entities {
		aw, aerr := armor.Encode(w, openpgp.PublicKeyType, nil)
		defer aw.Close()
		if aerr != nil {
			panic(aerr)
		}
		oerr := e.SerializePrivate(ioutil.Discard, nil) // Workaround Go Issue #6483
		if oerr != nil {
			panic(oerr)
		}
		oerr = e.Serialize(aw)
		if oerr != nil {
			panic(oerr)
		}
	}
}

func newSingleKeyServer() *testServer {
	e, err := openpgp.NewEntity("John Doe", "Test", "johndoe@example.com", nil)
	if err != nil {
		panic(err)
	}
	for _, id := range e.Identities {
		err := id.SelfSignature.SignUserId(id.UserId.Id, e.PrimaryKey, e.PrivateKey, nil)
		if err != nil {
			panic(err)
		}
	}
	ts := &testServer{
		entities: openpgp.EntityList([]*openpgp.Entity{e}),
	}
	ts.Server = httptest.NewServer(ts)
	return ts
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
