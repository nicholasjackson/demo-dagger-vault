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

type JWTAuth struct {
	Token string
	Role  string
	Path  string
}

type Vault struct {
	Namespace string
	Host      string

	Userpass *UserpassAuth
	JWT      *JWTAuth
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
	username string,
	password *Secret,
	// +optional
	// +default=userpass
	path string,
) *Vault {
	pass, _ := password.Plaintext(ctx)

	v.Userpass = &UserpassAuth{
		Username: username,
		Password: pass,
		Path:     path,
	}

	return v
}

func (v *Vault) WithJWTAuth(
	ctx context.Context,
	token *Secret,
	role string,
	// +optional
	// +default=jwt
	path string,
) *Vault {
	jwt, _ := token.Plaintext(ctx)

	v.JWT = &JWTAuth{
		Token: jwt,
		Role:  role,
		Path:  path,
	}

	return v
}

// GetSecretJSON returns a Vault secret as a JSON string
// this method corresponds to the Vault CLI command `vault kv get`
func (v *Vault) KVGet(
	ctx context.Context,
	secret string,
) (string, error) {
	c, err := v.getClient(ctx)
	if err != nil {
		return "", err
	}

	// get the version of the secrets engine
	dets, err := v.kvDetails(ctx, secret, c)
	if err != nil {
		return "", fmt.Errorf("unable to get secret details: %w", err)
	}

	log.Debug("Get secret", "path", dets.Path, "version", dets.Version)

	switch dets.Version {
	case "1":
		secret = strings.TrimPrefix(secret, dets.Path)

		resp, err := c.Secrets.KvV1Read(ctx, secret, vault.WithMountPath(dets.Path), vault.WithNamespace(v.Namespace))
		if err != nil {
			return "", fmt.Errorf("failed to read secret: %w", err)
		}

		js, _ := json.Marshal(resp.Data)

		return string(js), nil
	case "2":
		// if we have kv2 we need to add the /data element to the path
		secret = strings.TrimPrefix(secret, dets.Path)

		resp, err := c.Secrets.KvV2Read(ctx, secret, vault.WithMountPath(dets.Path), vault.WithNamespace(v.Namespace))
		if err != nil {
			return "", fmt.Errorf("failed to read secret: %w", err)
		}

		js, _ := json.Marshal(resp.Data.Data)

		return string(js), nil
	}

	return "", fmt.Errorf("unsupported version: %s", dets.Version)
}

type kvDetails struct {
	Path    string
	Version string
}

// kvDetails returns the details of a KV secret such as the path and version
func (v *Vault) kvDetails(
	ctx context.Context,
	secret string,
	c *vault.Client,
) (kvDetails, error) {
	secret = fmt.Sprintf("/sys/internal/ui/mounts/%s", secret)

	resp, err := c.Read(ctx, secret, vault.WithNamespace(v.Namespace))
	if err != nil {
		return kvDetails{}, fmt.Errorf("failed to read secret: %w", err)
	}

	kv := kvDetails{
		Path:    resp.Data["path"].(string),
		Version: resp.Data["options"].(map[string]interface{})["version"].(string),
	}

	return kv, nil
}

// Write writes a vault secret and returns the response as a JSON string
// this method corresponds to the Vault CLI command `vault write`
// optional params can be passed as a comma separated list of key=value pairs
func (v *Vault) Write(
	ctx context.Context,
	secret string,
	// +optional
	params string,
) (string, error) {
	c, err := v.getClient(ctx)
	if err != nil {
		return "", err
	}

	body := map[string]interface{}{}
	if params != "" {
		paramList := strings.Split(params, ",")
		for _, p := range paramList {
			kv := strings.Split(p, "=")
			if len(kv) == 2 {
				body[kv[0]] = kv[1]
			}
		}
	}

	resp, err := c.Write(ctx, secret, body, vault.WithNamespace(v.Namespace))
	if err != nil {
		return "", fmt.Errorf("failed to write secret: %w", err)
	}

	js, err := json.Marshal(resp.Data)
	if err != nil {
		return "", fmt.Errorf("failed to marshal secret to JSON: %w", err)
	}

	return string(js), nil
}

// Read returns a vault secret as a JSON string
// this method corresponds to the Vault CLI command `vault read`
func (v *Vault) Read(
	ctx context.Context,
	secret string,
) (string, error) {
	c, err := v.getClient(ctx)
	if err != nil {
		return "", err
	}

	resp, err := c.Read(ctx, secret, vault.WithNamespace(v.Namespace))
	if err != nil {
		return "", fmt.Errorf("failed to read secret: %w", err)
	}

	js, err := json.Marshal(resp.Data)
	if err != nil {
		return "", fmt.Errorf("failed to marshal secret to JSON: %w", err)
	}

	return string(js), nil
}

// TestWrite is a test function for the GetSecretJSON function
// example usage: dagger call test-write --host ${VAULT_ADDR} --namespace=${VAULT_NAMESPACE} --username=VAULT_USER --password=VAULT_PASSWORD --secret=kubernetes/hashitalks/creds/deployer-default --params="kubernetes_namespace=default"
func (v *Vault) TestWrite(
	ctx context.Context,
	host,
	namespace string,
	username,
	password *Secret,
	secret string,
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

	return v.Write(ctx, secret, params)
}

// TestKVGet is a test function for the GetSecretJSON function
// example usage: dagger call test-write --host ${VAULT_ADDR} --namespace=${VAULT_NAMESPACE} --username=VAULT_USER --password=VAULT_PASSWORD --secret=secrets/hashitalks/creds/deployment
func (v *Vault) TestKVGet(
	ctx context.Context,
	host,
	namespace string,
	username,
	password *Secret,
	secret string,
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

	return v.KVGet(ctx, secret)
}

func (v *Vault) getClient(ctx context.Context) (*vault.Client, error) {
	client, err := vault.New(
		vault.WithAddress(v.Host),
	)

	if err != nil {
		return nil, err
	}

	if v.Userpass != nil {
		vr, err := client.Auth.UserpassLogin(ctx, v.Userpass.Username, schema.UserpassLoginRequest{Password: v.Userpass.Password}, vault.WithNamespace(v.Namespace), vault.WithMountPath(v.Userpass.Path))
		if err != nil {
			return nil, fmt.Errorf("failed to login: %w", err)
		}

		log.Debug("Logged in as", "user", v.Userpass.Username)
		client.SetToken(vr.Auth.ClientToken)
	}

	if v.JWT != nil {
		vr, err := client.Auth.JwtLogin(ctx, schema.JwtLoginRequest{Jwt: v.JWT.Token, Role: v.JWT.Role}, vault.WithNamespace(v.Namespace), vault.WithMountPath(v.JWT.Path))
		if err != nil {
			return nil, fmt.Errorf("failed to login: %w", err)
		}

		log.Debug("Logged in as", "role", v.JWT.Role)
		client.SetToken(vr.Auth.ClientToken)
	}

	return client, nil
}
