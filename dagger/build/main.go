package main

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

var arches = []string{"amd64", "arm64"}
var dockerImage = "nicholasjackson/hashitalks2024"

type VaultSecrets struct {
	k8sAccessToken *Secret
	k8sAddr        string
	dockerUsername string
	dockerPassword *Secret
}

type Build struct {
}

// FetchDaggerCloudToken fetches the Dagger Cloud API token from Vault.
func (b *Build) FetchDaggerCloudToken(
	ctx context.Context,
	vaultAddr, vaultNamespace string,
	// +optional
	actionsRequestToken *Secret,
	// +optional
	actionsTokenURL string,
	// +optional
	circleCIOIDCToken *Secret,
) (string, error) {
	jwt, authPath := b.getJWTAuthDetails(ctx, actionsRequestToken, actionsTokenURL, circleCIOIDCToken)

	vc := dag.Vault().
		WithHost(vaultAddr).
		WithNamespace(vaultNamespace).
		WithJwtauth(jwt, "hashitalks-deployer", VaultWithJwtauthOpts{Path: authPath})

	jsSecret := vc.Kvget("secrets/hashitalks/deployment")
	if jsSecret == nil {
		return "", fmt.Errorf("failed to fetch secret")
	}

	// unmarshal the secret into an object
	js, _ := jsSecret.Plaintext(ctx)
	data := map[string]interface{}{}
	err := json.Unmarshal([]byte(js), &data)
	if err != nil {
		return "", err
	}

	return data["dagger_cloud_token"].(string), nil
}

// All runs the unit tests, builds the application, packages it in a container, and pushes it to the registry.
// It also fetches a secret from Vault and deploys the application to Kubernetes.
//
// If the optional parameters for Docker are not provided, the corresponding steps are skipped.
// If the optional parameters fro Vault and Kubernetes are not provided, the corresponding steps are skipped.
func (b *Build) All(
	ctx context.Context,
	src *Directory,
	vaultAddr string,
	// +optional
	vaultNamespace string,
	// +optional
	vaultUsername *Secret,
	// +optional
	vaultPassword *Secret,
	// +optional
	actionsRequestToken *Secret,
	// +optional
	actionsTokenURL string,
	// +optional
	circleCIOIDCToken *Secret,
) error {
	if vaultAddr == "" {
		return fmt.Errorf("vault address is required")
	}

	// run the unit tests
	err := b.UnitTest(ctx, src, false)
	if err != nil {
		return err
	}

	// build the application
	out, err := b.Build(ctx, src)
	if err != nil {
		return err
	}

	// get the latest git sha from the source
	sha, err := b.getGitSHA(ctx, src)
	if err != nil {
		return err
	}

	var secrets VaultSecrets

	// fetch the vault secrets using the vault userpass
	if vaultUsername != nil && vaultPassword != nil {
		user, _ := vaultUsername.Plaintext(ctx)

		secrets, err = b.fetchDeploymentSecretUserpass(ctx, vaultAddr, user, vaultPassword, vaultNamespace)
		if err != nil {
			return fmt.Errorf("failed to fetch deployment secret:%w", err)
		}
	}

	// fetch the vault secrets using the vault oidc auth
	if (actionsRequestToken != nil && actionsTokenURL != "") || circleCIOIDCToken != nil {
		jwt, authPath := b.getJWTAuthDetails(ctx, actionsRequestToken, actionsTokenURL, circleCIOIDCToken)

		secrets, err = b.fetchDeploymentSecretOIDC(ctx, vaultAddr, vaultNamespace, jwt, authPath)
		if err != nil {
			return fmt.Errorf("failed to fetch deployment secret:%w", err)
		}
	}

	err = b.DockerBuildAndPush(ctx, out, sha, secrets.dockerUsername, secrets.dockerPassword)
	if err != nil {
		return err
	}

	dep := src.File("/src/kubernetes/deploy.yaml")
	err = b.DeployToKubernetes(ctx, sha, secrets.k8sAccessToken, secrets.k8sAddr, dep)
	if err != nil {
		return fmt.Errorf("failed to deploy to Kubernetes:%w", err)
	}

	return nil
}

func (d *Build) UnitTest(ctx context.Context, src *Directory, withRace bool) error {
	cli := dag.Pipeline("unit-test")

	raceFlag := ""
	if withRace {
		raceFlag = "-race"
	}

	golang := cli.Container().
		From("golang:latest").
		WithDirectory("/files", src).
		WithMountedCache("/go/pkg/mod", d.goCache()).
		WithWorkdir("/files/src").
		WithExec([]string{"go", "test", "-v", raceFlag, "./..."})

	_, err := golang.Sync(ctx)

	return err
}

func (d *Build) Build(ctx context.Context, src *Directory) (*Directory, error) {
	cli := dag.Pipeline("build")

	// create empty directory to put build outputs
	outputs := dag.Directory()

	// get `golang` image
	golang := cli.Container().
		From("golang:latest").
		WithDirectory("/files", src).
		WithWorkdir("/files/src").
		WithMountedCache("/go/pkg/mod", d.goCache())

	for _, goarch := range arches {
		fmt.Println("Build for", goarch, "...")

		// create a directory for each os and arch
		path := fmt.Sprintf("/build/linux/%s/app", goarch)

		// set GOARCH and GOOS in the build environment
		build, err := golang.
			WithEnvVariable("CGO_ENABLED", "0").
			WithEnvVariable("GOOS", "linux").
			WithEnvVariable("GOARCH", goarch).
			WithExec([]string{"go", "build", "-o", path}).
			Sync(ctx)

		if err != nil {
			return nil, err
		}

		// get reference to build output directory in container
		outputs = outputs.WithFile(path, build.File(path))
	}

	return outputs, nil
}

func (d *Build) DockerBuildAndPush(ctx context.Context, bin *Directory, sha, dockerUsername string, dockerPassword *Secret) error {
	fmt.Println("Building Docker image...")

	cli := dag.Pipeline("docker-build")

	platormVariants := []*Container{}

	for _, goarch := range arches {
		fmt.Println("Create image for", goarch, "...")

		path := fmt.Sprintf("/build/linux/%s/app", goarch)

		// get `docker` image
		docker := cli.Container(ContainerOpts{Platform: Platform(fmt.Sprintf("linux/%s", goarch))}).
			From("alpine:latest").
			WithFile("/bin/app", bin.File(path)).
			WithExec([]string{"chmod", "+x", "/bin/app", "."}).
			WithEntrypoint([]string{"/bin/app"})

		platormVariants = append(platormVariants, docker)
	}

	// push the images to the registry
	digest, err := cli.Container().
		WithRegistryAuth("docker.io", dockerUsername, dockerPassword).
		Publish(
			ctx,
			fmt.Sprintf("%s:%s", dockerImage, sha),
			ContainerPublishOpts{
				PlatformVariants: platormVariants,
			})

	if err != nil {
		return err
	}

	fmt.Println("Docker image digest:", digest)

	return nil
}

func (d *Build) DeployToKubernetes(ctx context.Context, sha string, token *Secret, host string, deployment *File) error {
	fmt.Println("Deploy to Kubernetes...", host, sha)

	cli := dag.Pipeline("deploy-to-kubernetes")

	// get the contents of the deployment template
	dStr, err := deployment.Contents(ctx)
	if err != nil {
		return err
	}

	// replace the image and write the new deployment file
	newDep := strings.ReplaceAll(string(dStr), "##DOCKER_IMAGE##", fmt.Sprintf("%s:%s", dockerImage, sha))
	df := cli.Directory().WithNewFile("deploy.yaml", newDep)

	out, err := cli.Container().
		From("bitnami/kubectl").
		WithDirectory("/files", df).
		WithEnvVariable("CACHE_INVALIDATE", time.Now().String()).
		WithSecretVariable("KUBE_TOKEN", token).
		WithExec([]string{
			"apply",
			"-f", "/files/deploy.yaml",
			"--token", "$KUBE_TOKEN",
			"--server", host,
			"--insecure-skip-tls-verify",
		}).Stdout(ctx)
	if err != nil {
		return fmt.Errorf("failed to deploy to Kubernetes:\n %s", newDep)
	}

	fmt.Println("Kubectl output:", out)

	return nil
}

func (d *Build) fetchDeploymentSecretUserpass(ctx context.Context, vaultHost, vaultUsername string, vaultPassword *Secret, vaultNamespace string) (VaultSecrets, error) {
	fmt.Println("Fetch deployment secret from Vault...", vaultHost)

	cli := dag.Pipeline("fetch-deployment-secret-userpass")

	vc := cli.Vault().
		WithHost(vaultHost).
		WithNamespace(vaultNamespace).
		WithUserpassAuth(vaultUsername, vaultPassword)

	jsSecret := vc.Write("kubernetes/hashitalks/creds/deployer-default")
	if jsSecret == nil {
		return VaultSecrets{}, fmt.Errorf("failed to fetch deployment secret")
	}

	js, _ := jsSecret.Plaintext(ctx)
	data := map[string]interface{}{}
	err := json.Unmarshal([]byte(js), &data)
	if err != nil {
		return VaultSecrets{}, err
	}

	token := cli.SetSecret("access-token", data["service_account_token"].(string))

	// fetch the static secrets from Vault
	fmt.Println("Fetch static secret from Vault...", vaultHost)
	jsSecret = vc.Kvget("secrets/hashitalks/deployment")

	if jsSecret == nil {
		return VaultSecrets{}, fmt.Errorf("failed to fetch static secrets")
	}

	js, _ = jsSecret.Plaintext(ctx)
	err = json.Unmarshal([]byte(js), &data)
	if err != nil {
		return VaultSecrets{}, err
	}

	dockerPassword := cli.SetSecret("dockerPassword", data["docker_password"].(string))

	secrets := VaultSecrets{
		k8sAccessToken: token,
		k8sAddr:        data["kube_addr"].(string),
		dockerUsername: data["docker_username"].(string),
		dockerPassword: dockerPassword,
	}

	return secrets, nil
}

func (d *Build) fetchDeploymentSecretOIDC(ctx context.Context, vaultHost, vaultNamespace string, jwt *Secret, jwtAuthPath string) (VaultSecrets, error) {
	cli := dag.Pipeline("fetch-deployment-secret-oidc")

	vc := cli.Vault().
		WithHost(vaultHost).
		WithNamespace(vaultNamespace).
		WithJwtauth(jwt, "hashitalks-deployer", VaultWithJwtauthOpts{Path: jwtAuthPath})

	fmt.Println("Fetch deployment secret from Vault...", vaultHost)
	jsSecret := vc.Write("kubernetes/hashitalks/creds/deployer-default")
	if jsSecret == nil {
		return VaultSecrets{}, fmt.Errorf("failed to fetch deployment secret")
	}

	js, _ := jsSecret.Plaintext(ctx)

	// unmarshal the secret into an object
	data := map[string]interface{}{}
	err := json.Unmarshal([]byte(js), &data)
	if err != nil {
		return VaultSecrets{}, err
	}

	// set the k8s access token as a secret so that it does not leak
	token := cli.SetSecret("access-token", data["service_account_token"].(string))

	// fetch the static secrets from Vault
	fmt.Println("Fetch static secret from Vault...", vaultHost)
	jsSecret = vc.Kvget("secrets/hashitalks/deployment")
	if jsSecret == nil {
		return VaultSecrets{}, fmt.Errorf("failed to fetch static secrets")
	}

	err = json.Unmarshal([]byte(js), &data)
	if err != nil {
		return VaultSecrets{}, err
	}

	// set the docker password as a secret so that it does not leak
	dockerPassword := cli.SetSecret("dockerPassword", data["docker_password"].(string))

	secrets := VaultSecrets{
		k8sAccessToken: token,
		k8sAddr:        data["kube_addr"].(string),
		dockerUsername: data["docker_username"].(string),
		dockerPassword: dockerPassword,
	}

	return secrets, nil
}

func (d *Build) goCache() *CacheVolume {
	return dag.CacheVolume("go-cache")
}

func (d *Build) getGitSHA(ctx context.Context, src *Directory) (string, error) {
	cli := dag.Pipeline("get-git-sha")

	// get the latest git sha from the source
	ref, err := cli.Container().
		From("alpine/git").
		WithDirectory("/src", src).
		WithWorkdir("/src").
		WithExec([]string{"rev-parse", "HEAD"}).
		Stdout(ctx)

	if err != nil {
		return "", err
	}

	return strings.TrimSpace(ref), nil
}

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
