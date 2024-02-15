package main

import (
	"context"
	"fmt"
	"strings"
	"time"
)

var arches = []string{"amd64", "arm64"}
var dockerImage = "nicholasjackson/hashitalks2024"

type Build struct {
}

// All runs the unit tests, builds the application, packages it in a container, and pushes it to the registry.
// It also fetches a secret from Vault and deploys the application to Kubernetes.
func (b *Build) All(
	ctx context.Context,
	src *Directory,
	dockerUsername string,
	dockerPassword *Secret,
	kubeAddr string,
	kubeAccessToken *Secret,
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

	// get the latest git sha from the source
	sha, err := b.getGitSHA(ctx, src)
	if err != nil {
		return err
	}

	err = b.DockerBuildAndPush(ctx, out, sha, dockerUsername, dockerPassword)
	if err != nil {
		return err
	}

	dep := src.File("/src/kubernetes/deploy.yaml")
	err = b.DeployToKubernetes(ctx, sha, kubeAccessToken, kubeAddr, dep)
	if err != nil {
		return fmt.Errorf("failed to deploy to Kubernetes:%w", err)
	}

	return nil
}

// UnitTest runs the unit tests for the application.
func (d *Build) UnitTest(ctx context.Context, src *Directory, withRace bool) error {
	cli := dag.Pipeline("unit-test")

	raceFlag := ""
	if withRace {
		raceFlag = "-race"
	}

	golang := cli.Container().
		From("golang:1.22").
		WithDirectory("/files", src).
		WithMountedCache("/go/pkg/mod", d.goCache()).
		WithWorkdir("/files/src").
		WithExec([]string{"go", "test", "-v", raceFlag, "./..."})

	_, err := golang.Sync(ctx)

	return err
}

// Build compiles the application for multiple architectures.
func (d *Build) Build(ctx context.Context, src *Directory) (*Directory, error) {
	cli := dag.Pipeline("build")

	// create empty directory to put build outputs
	outputs := dag.Directory()

	// get `golang` image
	golang := cli.Container().
		From("golang:1.22").
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

// DockerBuildAndPush builds the Docker image for the application and pushes it to the registry.
func (d *Build) DockerBuildAndPush(ctx context.Context, bin *Directory, sha, dockerUsername string, dockerPassword *Secret) error {
	fmt.Println("Building Docker image...")

	cli := dag.Pipeline("docker-build")

	platormVariants := []*Container{}

	for _, goarch := range arches {
		fmt.Println("Create image for", goarch, "...")

		path := fmt.Sprintf("/build/linux/%s/app", goarch)

		// get `docker` image
		docker := cli.Container(ContainerOpts{Platform: Platform(fmt.Sprintf("linux/%s", goarch))}).
			From("alpine:3.19").
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

// DeployToKubernetes deploys the application to Kubernetes.
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

	tkn, _ := token.Plaintext(ctx)

	out, err := cli.Container().
		From("bitnami/kubectl:1.29").
		WithDirectory("/files", df).
		WithEnvVariable("CACHE_INVALIDATE", time.Now().String()).
		WithExec([]string{
			"apply",
			"-f", "/files/deploy.yaml",
			"--token", tkn,
			"--server", host,
			"--insecure-skip-tls-verify",
		}).Stdout(ctx)
	if err != nil {
		return fmt.Errorf("failed to deploy to Kubernetes:\n %s", newDep)
	}

	fmt.Println("Kubectl output:", out)

	return nil
}

// goCache returns the cache volume for the Go build environment.
func (d *Build) goCache() *CacheVolume {
	return dag.CacheVolume("go-cache")
}

// getGitSHA returns the latest git sha from the source repository
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
