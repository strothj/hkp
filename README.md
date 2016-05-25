# hkp [![GoDoc](https://godoc.org/github.com/strothj/hkp?status.png)](https://godoc.org/github.com/strothj/hkp)
`hkp` provides an OpenPGP HTTP Keyserver Protocol (HKP) client for Go.



## Example Usage
```go
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
```