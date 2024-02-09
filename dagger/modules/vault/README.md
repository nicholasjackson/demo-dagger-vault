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
- `path` (Optional string) - The path to use for the Vault secrets, defaults to `userpass`.

## GetSecretJSON
The `GetSecretJSON` function is used to get a secret from Vault and return it as a json formatted string.

### Parameters
- `secret` (string) - The path to the secret in Vault.
- `params` (Optional string) - The parameters to use for the secret in Vault, specified as as comma separated key value i.e `ttl=2h,policy=default`.
- `operationType` (Optional string) - The operation type to use for the secret in Vault, defaults to `read`.

### Example

```go
j, err := dag.Vault().
  WithNamespace("my-namespace").
  WithHost("https://vault.example.com").
  WithUserpassAuth(ctx, "my-username", "my-password").
  GetSecretJSON(ctx, "kubernetes/hashitalks/creds/deployer-default", "kubernetes_namespace=default", "write")
```

## Testing

```shell
dagger call test-get-secret --host ${VAULT_ADDR} --namespace=${VAULT_NAMESPACE} --username=VAULT_USER --password=VAULT_PASSWORD --secret=kubernetes/hashitalks/creds/deployer-default --params="kubernetes_namespace=default" --op-type=write
```