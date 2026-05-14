package main

import (
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
)

type Proxy struct {
	URL      string
	Username string
	Password string
}

func (p Proxy) HasAuthorizationCredentials() bool {
	return p.Username != ""
}

func (p Proxy) BasicAuthorizationHeader() string {
	auth := fmt.Sprintf("%s:%s", p.Username, p.Password)
	encodedAuth := base64.StdEncoding.EncodeToString([]byte(auth))
	return "Basic " + encodedAuth
}

func (p Proxy) HttpTransport() *http.Transport {
	proxyURLFunc := func(r *http.Request) (*url.URL, error) {
		return url.Parse(p.URL)
	}
	transport := &http.Transport{
		Proxy: proxyURLFunc,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}
	if p.HasAuthorizationCredentials() {
		transport.ProxyConnectHeader = http.Header{}
		transport.ProxyConnectHeader.Add("Proxy-Authorization", p.BasicAuthorizationHeader())
	}
	return transport
}
