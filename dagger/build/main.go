package main

import (
	"context"
	"encoding/json"
	"fmt"
)

var arches = []string{"amd64", "arm64"}
var dockerImage = "nicholasjackson/hashitalks2024:latest"

type Build struct {
}

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

	// package in a container and push to the registry
	if dockerUsername != nil && dockerPassword != nil {
		user, _ := dockerUsername.Plaintext(ctx)

		err = b.DockerBuildAndPush(ctx, out, user, dockerPassword)
		if err != nil {
			return err
		}
	}

	if vaultHost != "" && vaultUsername != nil && vaultPassword != nil && kubeDeployment != nil && kubeHost != "" {
		user, _ := vaultUsername.Plaintext(ctx)
		pass, _ := vaultPassword.Plaintext(ctx)

		secret, err := b.FetchDeploymentSecret(ctx, vaultHost, user, pass, vaultNamespace)
		if err != nil {
			return fmt.Errorf("failed to fetch deployment secret:%w", err)
		}

		err = b.DeployToKubernetes(ctx, secret, kubeHost, kubeDeployment)
		if err != nil {
			return fmt.Errorf("failed to deploy to Kubernetes:%w", err)
		}
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
		WithDirectory("/src", src).
		WithMountedCache("/go/pkg/mod", d.goCache()).
		WithWorkdir("/src").
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
		WithDirectory("/src", src).
		WithWorkdir("/src").
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

func (d *Build) DockerBuildAndPush(ctx context.Context, bin *Directory, dockerUsername string, dockerPassword *Secret) error {
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
			dockerImage,
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

func (d *Build) DeployToKubernetes(ctx context.Context, secret, host string, deployment *File) error {
	fmt.Println("Deploy to Kubernetes...", host)

	_, err := dag.Container().
		From("bitnami/kubectl").
		WithFile("/tmp/deployment.yaml", deployment).
		WithExec([]string{
			"apply",
			"-f", "/tmp/deployment.yaml",
			"--token", secret,
			"--server", host,
			"--insecure-skip-tls-verify",
		}).Sync(ctx)

	return err
}

func (d *Build) goCache() *CacheVolume {
	return dag.CacheVolume("go-cache")
}
