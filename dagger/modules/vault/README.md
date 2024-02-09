# Dagger module to access Vault Secrets

This module allows you to access Vault secrets from Dagger. It uses the Vault API to access the secrets.

## Testing

```shell
dagger call test-get-secret --host ${VAULT_ADDR} --namespace=${VAULT_NAMESPACE} --username=VAULT_USER --password=VAULT_PASSWORD --secret=kubernetes/hashitalks/creds/deployer-default --params="kubernetes_namespace=default" --op-type=write
```