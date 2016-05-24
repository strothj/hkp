package hkp

import (
	"encoding/hex"
	"errors"
	"net"
	"net/http"
	"net/url"
	"strings"

	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
	"golang.org/x/crypto/openpgp/packet"
	"golang.org/x/net/context"
	"golang.org/x/net/context/ctxhttp"
)

const (
	// UnsupportedKeyIDLength is returned on invalid keyID lengths. See
	// ParseKeyID().
	UnsupportedKeyIDLength = Error("invalid keyID length")

	// InvalidKeyIDBytes is returned when a keyID contains nonhex characters.
	InvalidKeyIDBytes = Error("keyID contains invalid characters")

	// UnsupportedSchemeError is returned for keyserver addresses which have
	// an unsupported scheme.
	UnsupportedSchemeError = Error("unsupported scheme")
)

const (
	baseRequestPath = "/pks/lookup"
)

// Client is an OpenPGP HTTP Keyserver Protocol (HKP) client.
type Client struct {
	client    *http.Client
	keyserver *Keyserver
}

// NewClient creates a new Client using the provided keyserver and http.Client.
// If client is nil a new one will be created.
// Panics if keyserver is nil.
func NewClient(keyserver *Keyserver, client *http.Client) *Client {
	if keyserver == nil {
		panic("keyserver nil")
	}
	if keyserver.url == nil {
		panic("keyserver url nil")
	}
	c := &Client{client: client, keyserver: keyserver}
	if c.client == nil {
		c.client = &http.Client{}
	}
	return c
}

// GetKeysByID requests keys from the keyserver that match the provided keyID.
func (c *Client) GetKeysByID(ctx context.Context, keyID *KeyID) (openpgp.EntityList, error) {
	if ctx == nil {
		panic("context nil")
	}
	if keyID == nil {
		panic("keyID nil")
	}
	// TODO: Test for empty Client
	var v url.Values = make(map[string][]string)
	v.Add("op", "get")
	v.Add("search", keyID.String())
	v.Add("options", "mr")
	url := &url.URL{
		Scheme:   c.keyserver.url.Scheme,
		Host:     c.keyserver.url.Host,
		Path:     baseRequestPath,
		RawQuery: v.Encode(),
	}
	resp, err := ctxhttp.Get(ctx, c.client, url.String())
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		// TODO: Create appropriate error for key not found
		return nil, errors.New("key not found")
	}
	if ct := resp.Header.Get("ContentType"); ct != "application/pgp-keys" {
		// TODO: Create appropriate error for wrong content type
		return nil, errors.New("wrong content type")
	}
	var blocks []*armor.Block
	for {
		b, _ := armor.Decode(resp.Body)
		if b == nil {
			break
		}
		blocks = append(blocks, b)
	}
	var entities []*openpgp.Entity
	if len(blocks) > 0 {
		r := packet.NewReader(blocks[0].Body)
		for i := 1; i < len(blocks); i++ {
			err := r.Push(blocks[i].Body)
			if err != nil {
				// TODO: Add clearer error message
				return nil, err
			}
		}
		for i := 0; i < len(blocks); i++ {
			e, err := openpgp.ReadEntity(r)
			if err != nil {
				// TODO: Add clearer error message
				return nil, err
			}
			entities = append(entities, e)
		}
	}
	return openpgp.EntityList(entities), nil
}

// Keyserver is an OpenPGP HTTP Keyserver Protocol (HKP) keyserver.
type Keyserver struct {
	url *url.URL
}

// ParseKeyserver parses rawurl into a Keyserver structure. It supports schemes
// http, https, hkp, hkps. If no scheme is provided it is assumed to be hkp.
func ParseKeyserver(rawurl string) (*Keyserver, error) {
	url, err := url.Parse(rawurl)
	if err != nil {
		return nil, err
	}
	if len(url.Scheme) == 0 {
		url, err = url.Parse("hkp://" + url.String())
		if err != nil {
			return nil, err
		}
	}
	url.Path = ""
	if strings.ToLower(url.Scheme) == "hkp" {
		url.Scheme = "http"
		host, port, err := net.SplitHostPort(url.Host)
		if err != nil {
			if nerr, b := err.(*net.AddrError); b {
				if nerr.Err == "missing port in address" {
					url.Host = url.Host + ":11371"
					return &Keyserver{url: url}, nil
				}
				return nil, err
			}
			return nil, err
		}
		if len(port) == 0 {
			url.Host = net.JoinHostPort(host, "11371")
		}
	}
	if strings.ToLower(url.Scheme) == "hkps" {
		url.Scheme = "https"
	}
	if strings.ToLower(url.Scheme) != "http" &&
		strings.ToLower(url.Scheme) != "https" {
		return nil, UnsupportedSchemeError
	}
	return &Keyserver{url: url}, nil
}

// KeyID represents an 8 digit (32-bit key ID), 16 digit (64-bit key ID),
// 32 digit (version 3 fingerprint), or 40 digit (version 4 fingerprint).
type KeyID struct {
	key string
}

func (k KeyID) String() string {
	return k.key
}

// ParseKeyID parses rawkeyid into a KeyID structure. It accepts an 8, 16, 32,
// or 40 digit hexadecimal string without the leading "0x".
func ParseKeyID(rawkeyid string) (*KeyID, error) {
	if len(rawkeyid) != 8 &&
		len(rawkeyid) != 16 &&
		len(rawkeyid) != 32 &&
		len(rawkeyid) != 40 {
		return nil, UnsupportedKeyIDLength
	}
	if _, err := hex.DecodeString(rawkeyid); err != nil {
		return nil, InvalidKeyIDBytes
	}
	return &KeyID{key: "0x" + rawkeyid}, nil
}

// Error represents an error constant. It implements the error interface.
type Error string

func (e Error) Error() string { return string(e) }
