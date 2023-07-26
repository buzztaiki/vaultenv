package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net/url"
	"os"
	"strings"
	"text/template"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/keyvault/azsecrets"
	"github.com/hashicorp/go-multierror"
)

type fetcher struct {
	clientCache map[string]*azsecrets.Client
	cred        azcore.TokenCredential
}

func main() {
	cred, err := newCredential()
	if err != nil {
		panic(err)
	}
	filter(fetcher{map[string]*azsecrets.Client{}, cred}, os.Stdin, os.Stdout)
}

func newCredential() (azcore.TokenCredential, error) {
	var errs error
	var creds []azcore.TokenCredential

	secretCred, err := azidentity.NewClientSecretCredential(
		os.Getenv("VAULTENV_AZURE_TENANT"),
		os.Getenv("VAULTENV_AZURE_USER"),
		os.Getenv("VAULTENV_AZURE_PASSWORD"),
		nil,
	)
	if err != nil {
		errs = multierror.Append(errs, err)
	} else {
		creds = append(creds, secretCred)
	}

	baseCred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		errs = multierror.Append(errs, err)
	} else {
		creds = append(creds, baseCred)
	}

	if len(creds) == 0 {
		return nil, errs
	}

	return azidentity.NewChainedTokenCredential(creds, nil)
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
	u, err := url.Parse(rawurl)
	if err != nil {
		return "", err
	}
	client, err := f.getClient((&url.URL{Scheme: u.Scheme, Host: u.Host}).String())
	if err != nil {
		return "", err
	}

	// https://kv.vault.azure.net/secrets/secretName
	// https://kv.vault.azure.net/secrets/secretName/version
	pathElems := strings.Split(u.Path, "/")[2:]

	var name, version string
	switch len(pathElems) {
	case 1:
		name = pathElems[0]
	case 2:
		name = pathElems[0]
		version = pathElems[1]
	default:
		return "", fmt.Errorf("invalid path: %q", u.Path)
	}

	secret, err := client.GetSecret(context.Background(), name, version, nil)
	if err != nil {
		return "", err
	}
	return *secret.Value, nil
}

func (f *fetcher) getClient(vaultURL string) (*azsecrets.Client, error) {
	if client, ok := f.clientCache[vaultURL]; ok {
		return client, nil
	}

	client, err := azsecrets.NewClient(vaultURL, f.cred, nil)
	if err != nil {
		return nil, err
	}
	f.clientCache[vaultURL] = client
	return client, nil
}
