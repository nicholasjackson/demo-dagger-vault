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

### Modify the Dagger pipeline

Let's modify the Dagger pipeline to use the secrets from Vault, first we are going to modify
if so that it runs locally using the secrets from Vault.

TODO: 
- [ ] modify code to use secrets from Vault using userpass auth
- [ ] run the pipeline locally
- [ ] modify code to use secrets from Vault using OIDC auth for GitHub Actions
- [ ] run the pipeline in GitHub Actions
- [ ] modify code to use secrets from Vault using OIDC auth for Circle CI
- [ ] run the pipeline in Circle CI
- [ ] summary