package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"strings"
	"time"
)

var arches = []string{"amd64", "arm64"}
var dockerImage = "nicholasjackson/hashitalks2024"

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
	// +optional
	vaultHost string,
	// +optional
	vaultUsername *Secret,
	// +optional
	vaultPassword *Secret,
	// +optional
	vaultNamespace string,
	// +optional
	dockerUsername *Secret,
	// +optional
	dockerPassword *Secret,
	// +optional
	kubeDeployment *File,
	// +optional
	kubeHost string,
) error {
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

	// skip packaging and pushing to the registry if the optional parameters are not provided
	if dockerUsername == nil || dockerPassword == nil {
		return nil
	}

	// get the latest git sha from the source
	sha, err := b.getGitSHA(ctx, src)
	if err != nil {
		return err
	}

	// package in a container and push to the registry
	user, _ := dockerUsername.Plaintext(ctx)

	err = b.DockerBuildAndPush(ctx, out, sha, user, dockerPassword)
	if err != nil {
		return err
	}

	// skip deployment if the optional parameters are not provided
	if vaultHost == "" || vaultUsername == nil || vaultPassword == nil || kubeDeployment == nil || kubeHost == "" {
		return fmt.Errorf("skipping deployment")
	}

	// deploy the application
	user, _ = vaultUsername.Plaintext(ctx)
	pass, _ := vaultPassword.Plaintext(ctx)

	secret, err := b.FetchDeploymentSecret(ctx, vaultHost, user, pass, vaultNamespace)
	if err != nil {
		return fmt.Errorf("failed to fetch deployment secret:%w", err)
	}

	err = b.DeployToKubernetes(ctx, sha, secret, kubeHost, kubeDeployment)
	if err != nil {
		return fmt.Errorf("failed to deploy to Kubernetes:%w", err)
	}

	return nil
}

func (d *Build) TestGetToken(ctx context.Context, actionsRequestToken *Secret, actionsTokenURL string, vaultAddr string) (string, error) {
	rq, err := http.NewRequest(http.MethodGet, actionsTokenURL, nil)
	if err != nil {
		return "", fmt.Errorf("unable to create request: %w", err)
	}

	// add the bearer token for the request
	token, _ := actionsRequestToken.Plaintext(ctx)
	rq.Header.Add("Authorization", fmt.Sprintf("bearer %s", token))

	// make the request
	resp, err := http.DefaultClient.Do(rq)
	if err != nil {
		return "", fmt.Errorf("unable to request token: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("expected status 200, got %d", resp.StatusCode)
	}

	// parse the response
	data := map[string]interface{}{}

	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("unable to read response body: %w", err)
	}

	json.Unmarshal(body, &data)

	gitHubJWT := data["value"].(string)

	fmt.Println("data: ", base64.StdEncoding.EncodeToString([]byte(gitHubJWT)))

	// authenticate with Vault and retrieve a K8s token
	_, err = dag.Vault().
		WithHost(vaultAddr).
		WithJwtauth(gitHubJWT, "hashitalks-deployer", VaultWithJwtauthOpts{Path: "jwt/github"}).
		GetSecretJSON(ctx, "kubernetes/hashitalks/roles/deployer-default")

	return "ok", err
	//return string(body), nil
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

func (d *Build) DockerBuildAndPush(ctx context.Context, bin *Directory, sha string, dockerUsername string, dockerPassword *Secret) error {
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

	// push the images to the registry
	digest, err := dag.Container().
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

func (d *Build) FetchDeploymentSecret(ctx context.Context, vaultHost, vaultUsername, vaultPassword, vaultNamespace string) (string, error) {
	fmt.Println("Fetch deployment secret from Vault...", vaultHost)

	js, err := dag.Vault().
		WithHost(vaultHost).
		WithNamespace(vaultNamespace).
		WithUserpassAuth(vaultUsername, vaultPassword).
		GetSecretJSON(ctx, "kubernetes/hashitalks/creds/deployer-default", VaultGetSecretJSONOpts{OperationType: "write"})

	if err != nil {
		return "", err
	}

	// unmarshal the secret into an object
	data := map[string]interface{}{}
	err = json.Unmarshal([]byte(js), &data)
	if err != nil {
		return "", err
	}

	return data["service_account_token"].(string), nil
}

func (d *Build) DeployToKubernetes(ctx context.Context, sha string, secret, host string, deployment *File) error {
	fmt.Println("Deploy to Kubernetes...", host, sha)

	// first replace the image tag in the deployment file
	dir, err := os.CreateTemp("", "")
	if err != nil {
		return fmt.Errorf("unable to create temp directory: %w", err)
	}
	defer os.RemoveAll(dir.Name())

	deployment.Export(ctx, path.Join(dir.Name(), "deployment.yaml"))
	dStr, err := os.ReadFile(path.Join(dir.Name(), "deployment.yaml"))
	if err != nil {
		return err
	}

	// replace the image and write the new deployment file
	newDep := strings.ReplaceAll(string(dStr), "##DOCKER_IMAGE##", fmt.Sprintf("%s:%s", dockerImage, sha))
	df := dag.Directory().WithNewFile("deployment.yaml", newDep)

	out, err := dag.Container().
		From("bitnami/kubectl").
		WithDirectory("/files", df).
		WithEnvVariable("CACHE_INVALIDATE", time.Now().String()).
		WithExec([]string{
			"apply",
			"-f", "/files/deployment.yaml",
			"--token", secret,
			"--server", host,
			"--insecure-skip-tls-verify",
		}).Stdout(ctx)
	if err != nil {
		return fmt.Errorf("failed to deploy to Kubernetes:\n %s", newDep)
	}

	fmt.Println("Kubectl output:", out)

	return fmt.Errorf("failed to deploy to Kubernetes:\n %s", newDep)
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
