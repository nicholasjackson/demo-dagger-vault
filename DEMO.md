# Demo Script

Dagger is a fantastic tool for decoupling your build pipeline from a specific CI/CD provider
like GitHub Actions, GitLab CI, or Circle CI. It allows you to define your build pipeline in a
simple and easy to understand way, in a language you are proficient in and then use the Dagger 
CLI to execute the build.

But, most pipelines need to access secrets, in this talk we are going to show you how to use
Vault Secrets from within your Dagger pipelines.

We are going to use a simple Go application that we will build and deploy to Kubernetes. We already
have most of the pipeline code written, but at present it is using static secrets. We are going to
modify the pipeline to use Vault to fetch the secrets.

While we will explain some of the concepts of Dagger and Vault, we do not have enough time to go into
these in detail. In our GitHub repo there is a README that explains in more detail and provides
some links to help you learn more.

Ok let's get started.

## Getting Started

First, let's take a look at the Dagger pipeline. We have a simple pipeline that builds the application.

At present the secrets are coming from a environment variables, but this means we need to
share the secrets with everyone who has access to the pipeline. We want to use Vault to store
the secrets and then fetch them at build time. By using Vault we also are able to use dynamic secrets
which are more secure. For example the Kuberentes service account token that we use to deploy the
application will be dynamically generated and have a short TTL.

### Show Dagger Pipeline

**Walk through the Dagger pipeline**

### Run the Dagger Pipeline

Let's run the Dagger pipeline to see what happens. You can see everything has worked correctly.
If we check our Kubernetes cluster we can see the application has been deployed.

```bash
dagger -m ./dagger/build call all \
  --src . \
  --docker-username=${DOCKER_USERNAME} \
  --docker-password=DOCKER_PASSWORD \
  --kube-addr=${KUBE_ADDR} \
  --kube-access-token=KUBE_TOKEN
```

Then we can check to see what has been deployed

```bash
kubectl get pods
```

## Using Vault Secrets

Now we are going to modify the pipeline to use Dagger to fetch the secrets from Vault. We are going
to need a combination of static secrets and dynamic secrets. The static secrets are things like the
credentials for DockerHub and the dynamic secrets are things like the Kubernetes service account token.

### Configure Vault, static secrets

Let's start with the static secrets.

First thing we need to do is to create the secrets in Vault, to do this I am going to use the Vault CLI.
I already have configured Vault authentication using `userpass` and I have these credentials saved as 
environment variables on my local computer.

Let's first login to Vault.

```bash
vault login --method=userpass username=$VAULT_USER password=$VAULT_PASSWORD
```

Then I am going to write these secrets to Vault.

```shell
vault kv put \
  secrets/hashitalks/deployment \
  kube_addr=${KUBE_ADDR} \
  docker_username=${DOCKER_USERNAME} \
  docker_password=${DOCKER_PASSWORD} \
  dagger_cloud_token=${DAGGER_CLOUD_TOKEN}
```

### Configure Vault, dynamic secrets

Next we need to create the dynamic secrets. We are going to use the Kubernetes secrets engine in Vault
let's enable and configure it.

```shell
vault secrets enable --path=kubernetes/hashitalks kubernetes
```

The following configuration is required to enable the Kubernetes secrets engine to talk to the Kubernetes cluster.
I have already created the service account token 

```bash
vault write kubernetes/hashitalks/config \
  kubernetes_ca_cert="$(op item get 'HashiTalks 2024' --fields 'Kubernetes.cluster_ca' | sed 's/"//g')" \
  kubernetes_host="$(op item get 'HashiTalks 2024' --fields 'Kubernetes.host')" \
  service_account_jwt="$(op item get 'HashiTalks 2024' --fields 'Kubernetes.sa_token')"
```


Now this has been configured we can create a roll that grants permission to the service account to
create and delete pods and services in the default namespace. We are using `default` for convenience
but in a real world scenario you would use a more specific namespace.

```bash
vault write kubernetes/hashitalks/roles/deployer-default \
  allowed_kubernetes_namespaces="default" \
  generated_role_rules="'rules': [{'apiGroups': [''], 'resources': ['pods','services'], 'verbs': ['get', 'list', 'create', 'update', 'patch', 'delete']},{'apiGroups': ['apps'], 'resources': ['deployments'], 'verbs': ['get', 'list', 'create', 'update', 'patch', 'delete']}]"
```

Ok now that is done, let's give it a quick test before we modify the pipeline.

```shell
export KUBE_TOKEN=$(vault write kubernetes/hashitalks/creds/deployer-default -format=json | jq -r .data.service_account_token)
```

```shell
kubectl get pods --server="${KUBE_ADDR}" --token="${KUBE_TOKEN}" -n default --insecure-skip-tls-verify
```

## Modify the Dagger pipeline

Let's modify the Dagger pipeline to use the secrets from Vault, first we are going to modify
if so that it runs locally using the secrets from Vault.

The first thing we need to write a function that can fetch the secrets from Vault. We are going to
use a Dagger module to do the actual interaction with Vault let's take a quick look at it.

[https://daggerverse.dev/mod/github.com/jumppad-labs/daggerverse/vault@4f140335b8c62d8e04a2fddcf559341d988b1832](https://daggerverse.dev/mod/github.com/jumppad-labs/daggerverse/vault@4f140335b8c62d8e04a2fddcf559341d988b1832)

We can add this module to our pipeline like so

```shell
dagger install github.com/jumppad-labs/daggerverse/vault@4f140335b8c62d8e04a2fddcf559341d988b1832
```

### Fetch the secrets from Vault using OIDC

Now we have that installed, lets modify the pipeline to get the secrets from Vault.
The first thing we need to do is to add a Go struct that will contain the secrets.

```go
type VaultSecrets struct {
	k8sAccessToken *Secret
	k8sAddr        string
	dockerUsername string
	dockerPassword *Secret
}
```

Next we can start to write a function that will fetch the secrets from Vault.
this function will use the `vault` module to fetch the secrets using jwt auth.

```go
func (d *Build) fetchDeploymentSecretOIDC(ctx context.Context, vaultHost, vaultNamespace string, jwt *Secret, jwtAuthPath string) (*VaultSecrets, error) {

}
```

Let's construct a new `Vault` client and then fetch the secrets from Vault. 
We are going to set the hostname and credentials for the Vault server, this module
is using the builder pattern to make it easy to configure the client.

```go
cli := dag.Pipeline("fetch-deployment-secret-userpass")

vc := cli.Vault().
	WithHost(vaultHost).
	WithNamespace(vaultNamespace).
	WithJwtauth(jwt, "hashitalks-deployer", VaultWithJwtauthOpts{Path: jwtAuthPath})
```

Once we have that we can now make a call to fetch the dynanmic secrets for the
kubernetes authentication.

```go
jsSecret := vc.Write("kubernetes/hashitalks/creds/deployer-default")
```

The data is returned from the Vault module as a Dagger `*Secret` this ensures that
it will not leak into any CLI or log output. It wraps the JSON that would be returned
from Vault os lets decode it.

```go
	// convert the secret to a string so that it can be unmarshalled
	js, err := jsSecret.Plaintext(ctx)
  if err != nil {
    return nil, err
  }

	// unmarshal the secret into an object
	data := map[string]interface{}{}
	err := json.Unmarshal([]byte(js), &data)
	if err != nil {
		return nil, err
	}
```

We can now get the token, since we are going to return this to the caller we need to
wrap it in a secret to again ensure that nothing leaks.

```go
token := cli.SetSecret("access-token", data["service_account_token"].(string))
```

We also need to get the static secrets, let's do the same process to get these.

```go
fmt.Println("Fetch static secret from Vault...", vaultHost)
jsSecret = vc.Kvget("secrets/hashitalks/deployment")
```

And again we need to decode the secret.

```go
js, err = jsSecret.Plaintext(ctx)
if err != nil {
  return nil, err
}

// unmarshal the secret into an object
err = json.Unmarshal([]byte(js), &data)
if err != nil {
	return nil, fmt.Errorf("failed to unmarshal deployment secret: %w", err)
}
```

Docker password is also a secret so let's wrap that in a dagger secret and we can
then return everything.

```go 
dockerPassword := cli.SetSecret("dockerPassword", data["docker_password"].(string))
```

```go
secrets := &VaultSecrets{
	k8sAccessToken: token,
	k8sAddr:        data["kube_addr"].(string),
	dockerUsername: data["docker_username"].(string),
	dockerPassword: dockerPassword,
}

return secrets, nil
}
```

### Modify the all function to use these secrets

Now we have that function written let's modify our code to use them.

We are going to modify the signature, we no longer need the static secrets 
but we do need the details for vault.

```go
func (b *Build) All(
	ctx context.Context,
	src *Directory,
	vaultAddr string,
	vaultNamespace string,
	// +optional
	actionsRequestToken *Secret,
	// +optional
	actionsTokenURL string,
	// +optional
	circleCIOIDCToken *Secret,
) error {
```

We are going to use OIDC to authenticate from both GitHub Actions and Circle CI,
however, they both have a slightly different way of fetching the token.
GithHub Actions provides a token URL that we can use to fetch the token, Circle CI
provides the token as an environment variable.

We are going to configure the authentication in Vault to do use these tokens in a moment.

But before we get to that, let's create a function that can fetch the token from the
GitHub OIDC service.

We are going to use the `github` module to fetch the token, this wraps the logic
to make the HTTP calls for the token. If we are using Circle CI we are going to 
return the value of the token as a secret.

One important thing to note is that we need to have separate auth paths for the different
auth methods, we are going to use `jwt/github` for GitHub Actions and `jwt/circleci` for Circle CI.
This is because the claims are different for the different services. You will see more
when we configure the auth in Vault.

```go
func (b *Build) getJWTAuthDetails(ctx context.Context, actionsRequestToken *Secret, actionsTokenURL string, circleCIOIDCToken *Secret) (*Secret, string) {
	cli := dag.Pipeline("get-jwt-auth-details")

	authPath := ""
	var jwt *Secret

	if actionsRequestToken != nil && actionsTokenURL != "" {
		authPath = "jwt/github"
		gitHubJWT, err := cli.Github().GetOidctoken(ctx, actionsRequestToken, actionsTokenURL)
		if err != nil {
			return nil, ""
		}

		jwt = cli.SetSecret("jwt", gitHubJWT)
	}

	if circleCIOIDCToken != nil {
		authPath = "jwt/circleci"
		jwt = circleCIOIDCToken
	}

	return jwt, authPath
}
```

Let's modify the `All` function to use this new function to get the JWT token and then

```go
jwt, authPath := b.getJWTAuthDetails(ctx, actionsRequestToken, actionsTokenURL, nil)

secrets, err = b.fetchDeploymentSecretOIDC(ctx, vaultAddr, vaultNamespace, jwt, authPath)
if err != nil {
	return fmt.Errorf("failed to fetch deployment secret:%w", err)
}
```

Now we can substitute the secrets into the pipeline.

```go
err = b.DockerBuildAndPush(ctx, out, sha, secrets.dockerUsername, secrets.dockerPassword)
if err != nil {
	return err
}
```

And 

```go
dep := src.File("/src/kubernetes/deploy.yaml")
err = b.DeployToKubernetes(ctx, sha, secrets.k8sAccessToken, secrets.k8sAddr, dep)
if err != nil {
	return fmt.Errorf("failed to deploy to Kubernetes:%w", err)
}
```

Ok all that worked, let's now show how we can use this from GitHub Actions and Circle CI.
First we need to configure OIDC authentication for Vault and GitHub.

## Configure Vault, OIDC auth

First thing we need to do is to enable the OIDC auth method in Vault.

```shell
vault auth enable --path=jwt/github jwt
```

Next we need to configure the OIDC auth method to validate the tokens that are provided by GitHub.

```shell
vault write auth/jwt/github/config \
  bound_issuer="https://token.actions.githubusercontent.com" \
  oidc_discovery_url="https://token.actions.githubusercontent.com"
```

When I was using my personal vault credentials I already had admin access
so I could fetch the secrets from Vault. But in a real world scenario we would need to create
a policy that controls what access is granted to the authenticated user.

```shell
vault policy write kubernetes-deployer - <<EOF
path "kubernetes/hashitalks/creds/deployer-default" {
  capabilities = [ "create", "update" ]
}

path "secrets/data/hashitalks/deployment" {
  capabilities = [ "read" ]
}
EOF
```

Finally we createa a role that binds the presented token to the policy, 
note the `repository` in the bound claims. This claim is automatically added 
by the GitHub OIDC service.

```shell
vault write auth/jwt/github/role/hashitalks-deployer -<<EOF
{
  "role_type": "jwt",
  "user_claim": "actor",
  "bound_claims": {
    "repository": "nicholasjackson/demo-dagger-vault"
  },
  "policies": ["kubernetes-deployer"],
  "ttl": "10m"
}
EOF
```

We will do the same thing for CircleCI, the steps for this configuration are 
all in the README.

## Setting up the GitHub Action

** SHOW IN GITHUB **

To use OIDC auth from a GitHub Action you need to set the permissions for the action to be able to
fetch the OIDC token. You can do this by adding the following to your workflow file.

```yaml
jobs:
  build:
    runs-on: ubuntu-latest
    permissions:
      id-token: write
      contents: read
```

Then you can use the following code to call the dagger pipeline passing the 
secrets to fetch the OIDC token.

```yaml
- name: Build and Deploy
  uses: dagger/dagger-for-github@v5
  with:
    verb: call 
    module: ./dagger/build
    args: all --src=. --vault-addr=$VAULT_ADDR --vault-namespace=$VAULT_NAMESPACE --actions-request-token=ACTIONS_ID_TOKEN_REQUEST_TOKEN --actions-token-url=$ACTIONS_ID_TOKEN_REQUEST_URL 
    version: "0.9.9"
```

[https://github.com/nicholasjackson/demo-dagger-vault](https://github.com/nicholasjackson/demo-dagger-vault)

Note that as an added bonus we have also configured the pipeline to use the new Dagger cloud, for caching.

Let's kick off the build by changing the code for our application.

While we are waiting for this to run, let's take a look at the Circle CI integration, it uses exactly the same
concepts. We do not have time to run through the full solution but everything you need to know to set
up the pipeline is in the README.

You can see that the pipeline has run successfully and the application has been deployed.

If we look at Circle CI we can see that the pipeline has also run successfully.