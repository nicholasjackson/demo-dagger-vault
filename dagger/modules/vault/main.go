package main

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/charmbracelet/log"
	"github.com/hashicorp/vault-client-go"
	"github.com/hashicorp/vault-client-go/schema"
)

type UserpassAuth struct {
	Username string
	Password string
	Path     string
}

type Vault struct {
	Namespace string
	Host      string

	Userpass *UserpassAuth
}

// WithNamespace sets the namespace for the Vault client
func (v *Vault) WithNamespace(namespace string) *Vault {
	v.Namespace = namespace
	return v
}

// WithHost sets the host for the Vault client
func (v *Vault) WithHost(host string) *Vault {
	v.Host = host
	return v
}

// WithUserpassAuth sets the userpass autrhentication for the Vault client
func (v *Vault) WithUserpassAuth(
	ctx context.Context,
	username, password string,
	// +optional
	// +default=userpass
	path string,
) *Vault {
	v.Userpass = &UserpassAuth{
		Username: username,
		Password: password,
		Path:     path,
	}

	return v
}

// GetSecretJSON returns a vault secret as a JSON string
func (v *Vault) GetSecretJSON(
	ctx context.Context,
	secret string,
	// +optional
	params string,
	// +optional
	// +default=read
	operationType string,
) (string, error) {
	c, err := v.getClient(ctx)
	if err != nil {
		return "", err
	}

	body := map[string]interface{}{}
	ps := strings.Split(params, ",")
	for _, p := range ps {
		kv := strings.Split(p, "=")
		if len(kv) == 2 {
			body[kv[0]] = kv[1]
		}
	}

	log.Debug("Getting secret", "secret", secret, "namespace", v.Namespace, "type", operationType, "params", params)

	var resp *vault.Response[map[string]interface{}]
	var respErr error

	switch operationType {
	case "read":
		resp, respErr = c.Read(ctx, secret, vault.WithNamespace(v.Namespace))
		if respErr != nil {
			return "", fmt.Errorf("failed to read secret: %w", respErr)
		}

	case "write":
		resp, respErr = c.Write(ctx, secret, body, vault.WithNamespace(v.Namespace))
		if respErr != nil {
			return "", fmt.Errorf("failed to read secret: %w", respErr)
		}
	}

	js, err := json.Marshal(resp.Data)
	if err != nil {
		return "", fmt.Errorf("failed to marshal secret: %w", err)
	}

	return string(js), nil
}

// TestGetSecret is a test function for the GetSecretJSON function
// example usage: dagger call test-get-secret --host ${VAULT_ADDR} --namespace=${VAULT_NAMESPACE} --username=VAULT_USER --password=VAULT_PASSWORD --secret=kubernetes/hashitalks/creds/deployer-default --params="kubernetes_namespace=default" --op-type=write
func (v *Vault) TestGetSecret(
	ctx context.Context,
	host,
	namespace string,
	username,
	password *Secret,
	secret string,
	// +optional
	// +default=read
	opType string,
	// +optional
	params string,
) (string, error) {
	// set the debug logger
	log.SetLevel(log.DebugLevel)

	v.Namespace = namespace
	v.Host = host

	u, _ := username.Plaintext(ctx)
	p, _ := password.Plaintext(ctx)

	v.Userpass = &UserpassAuth{
		Username: u,
		Password: p,
		Path:     "userpass",
	}

	d, err := v.GetSecretJSON(ctx, secret, params, opType)
	if err != nil {
		return "", err
	}

	return d, nil
}

func (v *Vault) getClient(ctx context.Context) (*vault.Client, error) {
	client, err := vault.New(
		vault.WithAddress(v.Host),
	)

	if err != nil {
		return nil, err
	}

	if v.Userpass != nil {
		vr, err := client.Auth.UserpassLogin(ctx, v.Userpass.Username, schema.UserpassLoginRequest{Password: v.Userpass.Password}, vault.WithNamespace(v.Namespace))
		if err != nil {
			return nil, fmt.Errorf("failed to login: %w", err)
		}

		log.Debug("Logged in as", "user", v.Userpass.Username)
		client.SetToken(vr.Auth.ClientToken)
	}

	return client, nil
}
