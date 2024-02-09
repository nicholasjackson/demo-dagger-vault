# HashiTalks 2024 Vault Secrets with Dagger Demo Repo

## Authenticate Vault as a user

You can use onepassword to set the userpass details for Vault

```bash
export VAULT_ADDR=$(op.exe item get "HashiTalks 2024" --fields "Vault.url")
export VAULT_USER=$(op.exe item get "HashiTalks 2024" --fields "Vault.username")
export VAULT_PASSWORD=$(op.exe item get "HashiTalks 2024" --fields "Vault.password")
export VAULT_NAMESPACE=$(op.exe item get "HashiTalks 2024" --fields "Vault.namespace")
```

Then login to Vault

```bash
vault login --method=userpass username=$VAULT_USER password=$VAULT_PASSWORD
```

## Kubernetes Secrets

To generate Kubernetes service account tokens that can be used to auth to Kubernetes
the Kubernetes secrets engine needs to be enabled.

First test the sa token that you have and can access the kubernetes cluster, a common
problem people have when coniguring Kubernetes secrets is a token that does not have
the correct permissions.

```bash
kubectl get namespace vault --server="$(op item get 'HashiTalks 2024' --fields 'Kubernetes.host')" --token="$(op item get 'HashiTalks 2024' --fields 'Kubernetes.sa_token')"
```

Now let's enable the Kubernetes secrets engine in Vault.

```bash
vault secrets enable --path=kubernetes/hashitalks kubernetes
```

Next we need to configure the Kubernetes secrets engine to talk to the Kubernetes cluster.
The secrets engine needs the following information:
* The Kubernetes API server address
* A service account token with the ability to create service accounts and service account tokens
* The CA certificate used to validate the Kubernetes API server's certificate

```bash
vault write kubernetes/hashitalks/config \
  kubernetes_ca_cert="$(op item get 'HashiTalks 2024' --fields 'Kubernetes.cluster_ca' | sed 's/"//g' | sed -z 's/\n/\\n/g' | sed -z 's/\\n$//')" \
  kubernetes_host="$(op item get 'HashiTalks 2024' --fields 'Kubernetes.host')" \
  service_account_jwt="$(op item get 'HashiTalks 2024' --fields 'Kubernetes.sa_token')"

vault write kubernetes/hashitalks/config \
  kubernetes_ca_cert="$(op item get 'HashiTalks 2024' --fields 'Kubernetes.cluster_ca' | sed 's/"//g')" \
  kubernetes_host="$(op item get 'HashiTalks 2024' --fields 'Kubernetes.host')" \
  service_account_jwt="$(op item get 'HashiTalks 2024' --fields 'Kubernetes.sa_token')"
```

To manage Kubernetes Vault needs the following permissions:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: k8s-full-secrets-abilities-with-labels
rules:
- apiGroups: [""]
  resources: ["namespaces"]
  verbs: ["get"]
- apiGroups: [""]
  resources: ["serviceaccounts", "serviceaccounts/token"]
  verbs: ["create", "update", "delete"]
- apiGroups: ["rbac.authorization.k8s.io"]
  resources: ["rolebindings", "clusterrolebindings"]
  verbs: ["create", "update", "delete"]
- apiGroups: ["rbac.authorization.k8s.io"]
  resources: ["roles", "clusterroles"]
  verbs: ["bind", "escalate", "create", "update", "delete"]

---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: vault-token-creator-binding
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: k8s-full-secrets-abilities-with-labels
subjects:
- kind: ServiceAccount
  name: vault
  namespace: vault
```

### Creating roles that allow access to the Kubernetes API

The following is an example role that allows listing pods in all namespaces.

#### list pods role
```bash
vault write kubernetes/hashitalks/roles/list-pods \
  allowed_kubernetes_namespaces="*" \
  generated_role_rules="'rules': [{'apiGroups': [''], 'resources': ['pods'], 'verbs': ['list']}]"
```

A token can be generate for the role using the following command:

```bash
vault write kubernetes/hashitalks/creds/list-pods kuberntes_namespace=default
```

This can then be used to access the Kubernetes API

```bash
export KUBE_TOKEN=$(vault write kubernetes/hashitalks/creds/list-pods kubernetes_namespace=vault -format=json | jq -r .data.service_account_token)
kubectl get pods --server="$(op item get 'HashiTalks 2024' --fields 'Kubernetes.host')" --token="${KUBE_TOKEN}" -n vault --insecure-skip-tls-verify
```

If you try to access a namespace that the role does not have access to you will get an error.

```bash
kubectl get pods --server="$(op item get 'HashiTalks 2024' --fields 'Kubernetes.host')" --token="${KUBE_TOKEN}" -n default --insecure-skip-tls-verify
```

```shell
Error from server (Forbidden): pods is forbidden: User "system:serviceaccount:vault:v-admin-de-list-pod-1707488231-r5wsy7e9wgjm7qr9ypjslw1n" cannot list resource "pods" in API group "" in the namespace "default"
```

We can now create further roles for admin

#### admin role

```bash
vault write kubernetes/hashitalks/roles/admin \
  allowed_kubernetes_namespaces="*" \
  generated_role_rules="'rules': [{'apiGroups': [''], 'resources': ['*'], 'verbs': ['*']}]"
```

Example: Create an admin token for the default namespace.

```shell
export KUBE_TOKEN=$(vault write kubernetes/hashitalks/creds/list-pods kubernetes_namespace=default -format=json | jq -r .data.service_account_token)
```

#### deployment role for the default namespace

The following role allows the creation and updating of pods in the default namespace.

```bash
vault write kubernetes/hashitalks/roles/deployer-default \
  allowed_kubernetes_namespaces="default" \
  generated_role_rules="'rules': [{'apiGroups': [''], 'resources': ['pods'], 'verbs': ['create', 'update']}]"
```

Example: Create a deployment token for the default namespace.

```shell
export KUBE_TOKEN=$(vault write kubernetes/hashitalks/creds/deployer-default -format=json | jq -r .data.service_account_token)
```

## Todo

- [x] Create a Vault server
- [x] Create a Kubernetes server
- [x] Configure Kubernetes Auth in Vault
- [x] Create Roles to access Kubernetes
- [ ] Configure OIDC Auth in Vault to enable GitHub Actions to login
- [ ] Configure OIDC Auth in Vault to enable CircleCI to login
- [ ] Create a Simple module to access Vault Secrets from Dagger
- [ ] Create a Dagger config to build an application and deploy to Kubernetes
- [ ] Add a GitHub Action to run Dagger
- [ ] Add a CircleCI config to run Dagger