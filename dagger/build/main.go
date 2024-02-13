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
	k8sAccessToken string
	k8sAddr        string
	dockerUsername string
	dockerPassword string
}

type Build struct {
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

	if vaultUsername != nil && vaultPassword != nil {
		// deploy the application
		user, _ := vaultUsername.Plaintext(ctx)
		pass, _ := vaultPassword.Plaintext(ctx)

		secrets, err = b.fetchDeploymentSecretUserpass(ctx, vaultAddr, user, pass, vaultNamespace)
		if err != nil {
			return fmt.Errorf("failed to fetch deployment secret:%w", err)
		}
	}

	if actionsRequestToken != nil && actionsTokenURL != "" {
		secrets, err = b.fetchDeploymentSecretOIDC(ctx, vaultAddr, vaultNamespace, actionsRequestToken, actionsTokenURL)
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
	raceFlag := ""
	if withRace {
		raceFlag = "-race"
	}

	golang := dag.Container().
		From("golang:latest").
		WithDirectory("/files", src).
		WithMountedCache("/go/pkg/mod", d.goCache()).
		WithWorkdir("/files/src").
		WithExec([]string{"go", "test", "-v", raceFlag, "./..."})

	_, err := golang.Sync(ctx)

	return err
}

func (d *Build) Build(ctx context.Context, src *Directory) (*Directory, error) {
	fmt.Println("Building...")

	// create empty directory to put build outputs
	outputs := dag.Directory()

	// get `golang` image
	golang := dag.Container().
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

func (d *Build) DockerBuildAndPush(ctx context.Context, bin *Directory, sha string, dockerUsername, dockerPassword string) error {
	fmt.Println("Building Docker image...")

	platormVariants := []*Container{}

	for _, goarch := range arches {
		fmt.Println("Create image for", goarch, "...")

		path := fmt.Sprintf("/build/linux/%s/app", goarch)

		// get `docker` image
		docker := dag.Container(ContainerOpts{Platform: Platform(fmt.Sprintf("linux/%s", goarch))}).
			From("alpine:latest").
			WithFile("/bin/app", bin.File(path)).
			WithExec([]string{"chmod", "+x", "/bin/app", "."}).
			WithEntrypoint([]string{"/bin/app"})

		platormVariants = append(platormVariants, docker)
	}

	secret := dag.SetSecret("dockerpassword", dockerPassword)

	// push the images to the registry
	digest, err := dag.Container().
		WithRegistryAuth("docker.io", dockerUsername, secret).
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

func (d *Build) DeployToKubernetes(ctx context.Context, sha string, secret, host string, deployment *File) error {
	fmt.Println("Deploy to Kubernetes...", host, sha)

	// get the contents of the deployment template
	dStr, err := deployment.Contents(ctx)
	if err != nil {
		return err
	}

	// replace the image and write the new deployment file
	newDep := strings.ReplaceAll(string(dStr), "##DOCKER_IMAGE##", fmt.Sprintf("%s:%s", dockerImage, sha))
	df := dag.Directory().WithNewFile("deploy.yaml", newDep)

	out, err := dag.Container().
		From("bitnami/kubectl").
		WithDirectory("/files", df).
		WithEnvVariable("CACHE_INVALIDATE", time.Now().String()).
		WithExec([]string{
			"apply",
			"-f", "/files/deploy.yaml",
			"--token", secret,
			"--server", host,
			"--insecure-skip-tls-verify",
		}).Stdout(ctx)
	if err != nil {
		return fmt.Errorf("failed to deploy to Kubernetes:\n %s", newDep)
	}

	fmt.Println("Kubectl output:", out)

	return nil
}

func (d *Build) fetchDeploymentSecretUserpass(ctx context.Context, vaultHost, vaultUsername, vaultPassword, vaultNamespace string) (VaultSecrets, error) {
	fmt.Println("Fetch deployment secret from Vault...", vaultHost)

	vc := dag.Vault().
		WithHost(vaultHost).
		WithNamespace(vaultNamespace).
		WithUserpassAuth(vaultUsername, vaultPassword)

	js, err := vc.GetSecretJSON(ctx, "kubernetes/hashitalks/creds/deployer-default", VaultGetSecretJSONOpts{OperationType: "write"})

	if err != nil {
		return VaultSecrets{}, err
	}

	// unmarshal the secret into an object
	data := map[string]interface{}{}
	err = json.Unmarshal([]byte(js), &data)
	if err != nil {
		return VaultSecrets{}, err
	}

	secrets := VaultSecrets{
		k8sAccessToken: data["service_account_token"].(string),
	}

	// fetch the static secrets from Vault
	fmt.Println("Fetch static secret from Vault...", vaultHost)
	js, err = vc.GetSecretJSON(ctx, "secrets/data/hashitalks/deployment")

	if err != nil {
		return VaultSecrets{}, err
	}

	err = json.Unmarshal([]byte(js), &data)
	if err != nil {
		return VaultSecrets{}, err
	}

	data = data["data"].(map[string]interface{})
	secrets.dockerUsername = data["docker_username"].(string)
	secrets.dockerPassword = data["docker_password"].(string)
	secrets.k8sAddr = data["kube_addr"].(string)

	return secrets, nil
}

func (d *Build) fetchDeploymentSecretOIDC(ctx context.Context, vaultHost, vaultNamespace string, actionsRequestToken *Secret, actionsTokenURL string) (VaultSecrets, error) {
	fmt.Println("Fetch deployment secret from Vault...", vaultHost)

	gitHubJWT, err := dag.Github().GetOidctoken(ctx, actionsRequestToken, actionsTokenURL)
	if err != nil {
		return VaultSecrets{}, fmt.Errorf("failed to get GitHub OIDC token: %w", err)
	}

	vc := dag.Vault().
		WithHost(vaultHost).
		WithNamespace(vaultNamespace).
		WithJwtauth(gitHubJWT, "hashitalks-deployer", VaultWithJwtauthOpts{Path: "jwt/github"})

	js, err := vc.GetSecretJSON(ctx, "kubernetes/hashitalks/creds/deployer-default", VaultGetSecretJSONOpts{OperationType: "write"})

	if err != nil {
		return VaultSecrets{}, err
	}

	// unmarshal the secret into an object
	data := map[string]interface{}{}
	err = json.Unmarshal([]byte(js), &data)
	if err != nil {
		return VaultSecrets{}, err
	}

	secrets := VaultSecrets{
		k8sAccessToken: data["service_account_token"].(string),
	}

	// fetch the static secrets from Vault
	fmt.Println("Fetch static secret from Vault...", vaultHost)
	js, err = vc.GetSecretJSON(ctx, "secrets/data/hashitalks/deployment")

	if err != nil {
		return VaultSecrets{}, err
	}

	err = json.Unmarshal([]byte(js), &data)
	if err != nil {
		return VaultSecrets{}, err
	}

	data = data["data"].(map[string]interface{})
	secrets.dockerUsername = data["docker_username"].(string)
	secrets.dockerPassword = data["docker_password"].(string)
	secrets.k8sAddr = data["kube_addr"].(string)

	return secrets, nil
}

func (d *Build) goCache() *CacheVolume {
	return dag.CacheVolume("go-cache")
}

func (d *Build) getGitSHA(ctx context.Context, src *Directory) (string, error) {
	// get the latest git sha from the source
	ref, err := dag.Container().
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
