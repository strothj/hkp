package hkp

import (
	"encoding/hex"
	"net"
	"net/http"
	"net/url"
	"strings"

	"golang.org/x/crypto/openpgp"
	"golang.org/x/net/context"
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

// Client is an OpenPGP HTTP Keyserver Protocol (HKP) client.
type Client struct {
	//
}

// NewClient creates a new Client using the provided keyserver and http.Client.
func NewClient(keyserver *Keyserver, client *http.Client) *Client {
	panic("Not Implemented")
}

// GetKeysByID requests keys from the keyserver that match the provided keyID.
func (c *Client) GetKeysByID(ctx context.Context, keyID *KeyID) (openpgp.EntityList, error) {
	panic("Not Implemented")
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
