package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"text/template"
	"time"
)

type httpClient interface {
	Do(req *http.Request) (*http.Response, error)
}
type fetcher struct {
	client        httpClient
	tokenProvider tokenProvider
	token         string
}

type tokenProvider interface {
	Token() (string, error)
}

var errTokenProviderNotAvailable = errors.New("token provider not available")

func main() {
	client := &http.Client{
		Timeout: time.Second * 5,
	}

	tokenProvider := tokenProviderChain{
		[]tokenProvider{
			&clientCredentialTokenProvider{
				client:       client,
				clientId:     os.Getenv("VAULTENV_AZURE_USER"),
				clientSecret: os.Getenv("VAULTENV_AZURE_PASSWORD"),
				tenant:       os.Getenv("VAULTENV_AZURE_TENANT"),
			},
			&vmIdentityTokenProvider{client},
		}}
	filter(fetcher{client, &tokenProvider, ""}, os.Stdin, os.Stdout)
}

func filter(f fetcher, in io.Reader, out io.Writer) {
	t := template.New(".env").Funcs(template.FuncMap{
		"kv": f.fetch,
	})
	scanner := bufio.NewScanner(in)
	for scanner.Scan() {
		if err := scanner.Err(); err != nil {
			panic(err)
		}
		line := scanner.Text()
		if line != "" {
			err := template.Must(t.Parse(line)).Execute(out, nil)
			if err != nil {
				panic(err)
			}
		}
		out.Write([]byte{'\n'})
	}
}

func (f *fetcher) fetch(rawurl string) (string, error) {
	url, err := url.Parse(rawurl)
	if err != nil {
		return "", err
	}
	if !strings.HasSuffix(url.Hostname(), "vault.azure.net") {
		return "", fmt.Errorf("Invalid url - %s", rawurl)
	}
	b, err := f.getToken()
	if err != nil {
		return "", err
	}
	req, err := http.NewRequest("GET", rawurl+"?api-version=7.0", nil)
	if err != nil {
		return "", err
	}
	req.Header.Add("Authorization", "Bearer "+b)
	req.Header.Add("Accept", "application/json")
	res, err := f.client.Do(req)
	if err != nil {
		return "", err
	}
	if res.StatusCode != 200 {
		return "", fmt.Errorf("GET %s - %s", url, res.Status)
	}
	defer res.Body.Close()
	var result struct {
		Value string `json:"value"`
	}
	decoder := json.NewDecoder(res.Body)
	if err = decoder.Decode(&result); err != nil {
		return "", err
	}

	return result.Value, nil
}

func (f *fetcher) getToken() (string, error) {
	if f.token != "" {
		return f.token, nil
	}
	token, err := f.tokenProvider.Token()
	if err != nil {
		return "", fmt.Errorf("failed to get token: %w", err)
	}
	f.token = token
	return token, nil
}

type clientCredentialTokenProvider struct {
	client       httpClient
	clientId     string
	clientSecret string
	tenant       string
}

func (p *clientCredentialTokenProvider) Token() (string, error) {
	if p.clientId == "" {
		return "", errTokenProviderNotAvailable
	}

	values := url.Values{}
	values.Set("grant_type", "client_credentials")
	values.Add("client_id", p.clientId)
	values.Add("client_secret", p.clientSecret)
	values.Add("resource", "https://vault.azure.net")
	req, err := http.NewRequest("GET", fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/token", p.tenant), strings.NewReader(values.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	return fetchToken(p.client, req)
}

type vmIdentityTokenProvider struct {
	client httpClient
}

func (p *vmIdentityTokenProvider) Token() (string, error) {
	req, err := http.NewRequest("GET", "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2019-06-04&resource=https%3A%2F%2Fvault.azure.net", nil)
	if err != nil {
		return "", err
	}
	req.Header.Add("Metadata", "true")
	return fetchToken(p.client, req)
}

func fetchToken(client httpClient, req *http.Request) (string, error) {
	res, err := client.Do(req)
	if err != nil {
		return "", err
	}
	if res.StatusCode != 200 {
		return "", errors.New(res.Status)
	}
	defer res.Body.Close()
	var auth struct {
		Token string `json:"access_token"`
	}
	decoder := json.NewDecoder(res.Body)
	if err := decoder.Decode(&auth); err != nil {
		return "", fmt.Errorf("failed to decode token: %w", err)
	}

	return auth.Token, nil
}

type tokenProviderChain struct {
	providers []tokenProvider
}

func (p *tokenProviderChain) Token() (string, error) {
	for _, provider := range p.providers {
		token, err := provider.Token()
		if errors.Is(err, errTokenProviderNotAvailable) {
			continue
		}
		if err != nil {
			return "", fmt.Errorf("%T: %w", provider, err)
		}
		return token, nil
	}

	return "", errTokenProviderNotAvailable
}
