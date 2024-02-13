# Dagger module to access Vault Secrets

This module allows you to access Vault secrets from Dagger. It uses the Vault API to access the secrets.

## WithNamespace
The `WithNamespace` function is used to set the namespace for the Vault secrets. This function is only needed if you are 
using Vault enterprise.

### Parameters
- `namespace` (string) - The namespace to use for the Vault secrets.

## WithHost
The `WithHost` function is used to set the host for the Vault secrets.

### Parameters
- `host` (string) - The host to use for the Vault secrets.


## WithUserpassAuth
The `WithUserpassAuth` function is used to set details for authnticating with Vault using
userpass.

### Parameters
- `username` (string) - The username to use for the Vault secrets.
- `password` (string) - The password to use for the Vault secrets.
- `path` (Optional string) - The path to use for the auth mount, defaults to `userpass`.


## WithJWTAuth
The `WithJWTAuth` function is used to set the details for authenticating with Vault using
JWT tokens.

### Parameters
- `token` (string) - The JWT token to use or authentication.
- `role` (string) - The Vault role to use. 
- `path` (Optional string) - The path to use for the auth mount, defaults to `jwt`.


## Write
The `Write` function is used to write data to Vault, it corresponds to the Vault CLI command `vault write`.

### Parameters
- `secret` (string) - The path to the secret in Vault.
- `params` (Optional string) - The parameters to use for the secret in Vault, specified as as comma separated key value i.e `ttl=2h,policy=default`.

### Returns
- `string` - The secret from Vault as a JSON formatted string.
- `error` - An error if the secret could not be retrieved.

### Example

```go
pass := dag.SetSecret("password", "my-value")

j, err := dag.Vault().
  WithNamespace("my-namespace").
  WithHost("https://vault.example.com").
  WithUserpassAuth(ctx, "my-username", pass).
  Write(ctx, "kubernetes/hashitalks/creds/deployer-default", "kubernetes_namespace=default")

// convert the json string to a map
var data map[string]interface{}
err = json.Unmarshal([]byte(j), &data)
```

## Read
The `Read` function is used to write data to Vault, it corresponds to the Vault CLI command `vault read`.

### Parameters
- `secret` (string) - The path to the secret in Vault.

### Returns
- `string` - The secret from Vault as a JSON formatted string.
- `error` - An error if the secret could not be retrieved.

### Example

```go
pass := dag.SetSecret("password", "my-value")

j, err := dag.Vault().
  WithNamespace("my-namespace").
  WithHost("https://vault.example.com").
  WithUserpassAuth(ctx, "my-username", pass).
  Read(ctx, "secrets/data/hashitalks/deployer") 
```

## KVGet
The `KVGet` function is used to write read a secret from the Vault KV. It corresponds to the Vault CLI command `vault kv get`.
Like the `cli` command the secret path does not need to include the addtional path `data` for version 2 secret engines.
The version of the secret engine is automatically determined.

### Parameters
- `secret` (string) - The path to the secret in Vault.

### Returns
- `string` - The secret from Vault as a JSON formatted string.
- `error` - An error if the secret could not be retrieved.

### Example

```go
pass := dag.SetSecret("password", "my-value")

j, err := dag.Vault().
  WithNamespace("my-namespace").
  WithHost("https://vault.example.com").
  WithUserpassAuth(ctx, "my-username", pass).
  Kvget(ctx, "secrets/hashitalks/deployer") 

// convert the json string to a map, note like the cli command the returned json string
// does not include the additional `data` node for version 2 secret engines
var data map[string]interface{}
err = json.Unmarshal([]byte(j), &data)
```

## Testing

```shell
dagger call test-get-secret --host ${VAULT_ADDR} --namespace=${VAULT_NAMESPACE} --username=VAULT_USER --password=VAULT_PASSWORD --secret=kubernetes/hashitalks/creds/deployer-default --params="kubernetes_namespace=default" --op-type=write
```