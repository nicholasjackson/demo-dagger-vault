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
	username string
	password string
	path     string
}

type Vault struct {
	namespace string
	host      string

	userpass *UserpassAuth
}

func (v *Vault) WithNamespace(namespace string) *Vault {
	v.namespace = namespace
	return v
}

func (v *Vault) WithHost(host string) *Vault {
	v.host = host
	return v
}

func (v *Vault) WtihUserpassAuth(ctx context.Context, username, password string, path Optional[string]) *Vault {
	v.userpass = &UserpassAuth{
		username: username,
		password: password,
		path:     path.GetOr("userpass"),
	}

	return v
}

func (v *Vault) GetSecretJSON(ctx context.Context, secret string, params Optional[string], operationType Optional[string]) (string, error) {
	// if the operation type is not set, default to read
	secretType := operationType.GetOr("read")

	c, err := v.getClient(ctx)
	if err != nil {
		return "", err
	}

	// parse the params
	sp := params.GetOr("")

	body := map[string]interface{}{}
	ps := strings.Split(sp, ",")
	for _, p := range ps {
		kv := strings.Split(p, "=")
		if len(kv) == 2 {
			body[kv[0]] = kv[1]
		}
	}

	log.Debug("Getting secret", "secret", secret, "namespace", v.namespace, "type", secretType, "params", params)

	var resp *vault.Response[map[string]interface{}]
	var respErr error

	switch secretType {
	case "read":
		resp, respErr = c.Read(ctx, secret, vault.WithNamespace(v.namespace))
		if err != nil {
			return "", fmt.Errorf("failed to read secret: %w", respErr)
		}

	case "write":
		resp, respErr = c.Write(ctx, secret, body, vault.WithNamespace(v.namespace))
		if err != nil {
			return "", fmt.Errorf("failed to read secret: %w", respErr)
		}
	}

	js, err := json.Marshal(resp.Data)
	if err != nil {
		return "", fmt.Errorf("failed to marshal secret: %w", err)
	}

	return string(js), nil
}

func (v *Vault) TestGetSecret(ctx context.Context, host, namespace string, username, password *Secret, secret string, params string, opType string) (string, error) {
	// set the debug logger
	log.SetLevel(log.DebugLevel)

	v.namespace = namespace
	v.host = host

	u, _ := username.Plaintext(ctx)
	p, _ := password.Plaintext(ctx)

	v.userpass = &UserpassAuth{
		username: u,
		password: p,
		path:     "userpass",
	}

	d, err := v.GetSecretJSON(ctx, secret, Opt[string](params), Opt[string](opType))
	if err != nil {
		return "", err
	}

	return d, nil
}

func (v *Vault) getClient(ctx context.Context) (*vault.Client, error) {
	client, err := vault.New(
		vault.WithAddress(v.host),
	)

	if err != nil {
		return nil, err
	}

	if v.userpass != nil {
		vr, err := client.Auth.UserpassLogin(ctx, v.userpass.username, schema.UserpassLoginRequest{Password: v.userpass.password}, vault.WithNamespace(v.namespace))
		if err != nil {
			return nil, fmt.Errorf("failed to login: %w", err)
		}

		log.Debug("Logged in as", "user", v.userpass.username)
		client.SetToken(vr.Auth.ClientToken)
	}

	return client, nil
}
