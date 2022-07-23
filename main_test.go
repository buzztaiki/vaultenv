package main

import (
	"bytes"
	"errors"
	"io/ioutil"
	"net/http"
	"strings"
	"testing"
)

type dummyClient struct{}

func (c *dummyClient) Do(req *http.Request) (*http.Response, error) {
	var body string
	if strings.HasPrefix(req.URL.String(), "http://169.254.169.254") {
		body = `{
  "access_token": "TOKEN_WITH_VM_IDENTITY",
  "refresh_token": "",
  "expires_in": "3599",
  "expires_on": "1506484173",
  "not_before": "1506480273",
  "resource": "https://vault.azure.net/",
  "token_type": "Bearer"
}`
	} else if strings.HasPrefix(req.URL.String(), "https://login.microsoftonline.com") {
		body = `{
  "access_token": "TOKEN_WITH_CLIENT_CREDENTIAL",
  "refresh_token": "",
  "expires_in": "3599",
  "expires_on": "1506484173",
  "not_before": "1506480273",
  "resource": "https://vault.azure.net/",
  "token_type": "Bearer"
}`
	} else if req.Header.Get("Authorization") == "Bearer TOKEN_WITH_VM_IDENTITY" {
		body = `{
  "value": "mysecretvalue1",
  "id": "https://example.vault.azure.net/secrets/pass/4387e9f3d6e14c459867679a90fd0f79",
  "attributes": {
    "enabled": true,
    "created": 1493938410,
    "updated": 1493938410,
    "recoveryLevel": "Recoverable+Purgeable"
  }
}`
	} else {
		return nil, errors.New("Unexpected request")
	}
	return &http.Response{
		Status:     "200 OK",
		StatusCode: 200,
		Body:       ioutil.NopCloser(bytes.NewBufferString(body)),
	}, nil
}

func TestClientCredentialTokenProvider(t *testing.T) {
	client := &dummyClient{}
	t.Run("no client_id", func(t *testing.T) {
		provider := &clientCredentialTokenProvider{client, "", "", ""}
		_, err := provider.Token()
		if want := errTokenProviderNotAvailable; !errors.Is(err, want) {
			t.Errorf("got:%q, want:%q", err, want)
		}
	})
	t.Run("valid client_id", func(t *testing.T) {
		provider := &clientCredentialTokenProvider{
			client:       client,
			clientId:     "b3a0fa1e-2a56-44c5-9ec1-f95921243ed7",
			clientSecret: "7a724b98-f30e-4991-a020-fb56d12277e1",
			tenant:       "5a9c134c-c9d6-4b9c-b588-94d3096dbf4c",
		}
		token, err := provider.Token()
		if err != nil {
			t.Fatal(err)
		}
		if want := "TOKEN_WITH_CLIENT_CREDENTIAL"; token != want {
			t.Errorf("got:%s, want:%s", token, want)
		}
	})
}

func TestVmIdentityTokenProvider(t *testing.T) {
	client := &dummyClient{}
	provider := &vmIdentityTokenProvider{client}
	token, err := provider.Token()
	if err != nil {
		t.Fatal(err)
	}
	if want := "TOKEN_WITH_VM_IDENTITY"; token != want {
		t.Errorf("got:%s, want:%s", token, want)
	}

}

type dummyTokenProvider struct {
	token string
	err   error
}

func (p dummyTokenProvider) Token() (string, error) {
	return p.token, p.err
}

func TestTokenProviderChain(t *testing.T) {
	errna := errTokenProviderNotAvailable
	err1 := errors.New("error1")
	err2 := errors.New("error2")
	type dummy = dummyTokenProvider

	tests := []struct {
		name      string
		providers []tokenProvider
		wantToken string
		wantError error
	}{
		{"simple",
			[]tokenProvider{dummy{"token1", nil}},
			"token1", nil},
		{"found, found",
			[]tokenProvider{dummy{"token1", nil}, dummy{"token2", nil}},
			"token1", nil},
		{"n/a, found",
			[]tokenProvider{dummy{"", errna}, dummy{"token2", nil}},
			"token2", nil},
		{"no provider",
			[]tokenProvider{},
			"", errna},
		{"error",
			[]tokenProvider{dummy{"", err1}},
			"", err1},
		{"error, found",
			[]tokenProvider{dummy{"", err1}, dummy{"token2", nil}},
			"", err1},
		{"found, error",
			[]tokenProvider{dummy{"token1", nil}, dummy{"", err2}},
			"token1", nil},
		{"error, error",
			[]tokenProvider{dummy{"", err1}, dummy{"", err2}},
			"", err1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider := &tokenProviderChain{tt.providers}
			token, err := provider.Token()
			if !errors.Is(err, tt.wantError) {
				t.Errorf("got:%q want:%q", err, tt.wantError)
			}
			if token != tt.wantToken {
				t.Errorf("got:%q want:%q", token, tt.wantToken)
			}
		})
	}

}

func setupTestFetcher() fetcher {
	client := &dummyClient{}
	return fetcher{client, &vmIdentityTokenProvider{client}, ""}
}

func TestValidTemplate(t *testing.T) {
	var b bytes.Buffer
	template := `USER=foo@example.com
PASSWORD={{ kv "https://example.vault.azure.net/secrets/pass" }}
`
	expected := `USER=foo@example.com
PASSWORD=mysecretvalue1
`
	r := strings.NewReader(template)
	filter(setupTestFetcher(), r, &b)
	if b.String() != expected {
		t.Fatalf("got:%s want:%s", b.String(), expected)
	}
}

func TestInvalidUrl(t *testing.T) {
	var b bytes.Buffer
	template := `USER=foo@example.com
PASSWORD={{ kv "https://invalid.sensyn.net/secrets/pass" }}
`
	r := strings.NewReader(template)
	defer func() {
		recover()
	}()
	filter(setupTestFetcher(), r, &b)
	t.Fatalf("must be panic")
}

func TestEmptyLine(t *testing.T) {
	var b bytes.Buffer
	template := `USER=foo@example.com

PASSWORD=mysecretvalue1
`
	expected := `USER=foo@example.com

PASSWORD=mysecretvalue1
`
	r := strings.NewReader(template)
	filter(setupTestFetcher(), r, &b)
	if b.String() != expected {
		t.Fatalf("got:%s want:%s", b.String(), expected)
	}
}
