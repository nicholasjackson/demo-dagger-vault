package main

import (
	"context"
	"fmt"
)

var arches = []string{"amd64", "arm64"}
var dockerImage = "nicholasjackson/hashitalks2024:latest"

type Build struct {
}

func (b *Build) All(ctx context.Context, src *Directory, vaultUsername, vaultPassword, dockerUsername, dockerPassword Optional[*Secret]) error {
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
	du, duOK := dockerUsername.Get()
	dp, dpOK := dockerPassword.Get()

	if duOK && dpOK {
		user, _ := du.Plaintext(ctx)
		pass, _ := dp.Plaintext(ctx)

		err = b.DockerBuildAndPush(ctx, out, user, pass)
		if err != nil {
			return err
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

func (d *Build) DockerBuildAndPush(ctx context.Context, bin *Directory, dockerUsername, dockerPassword string) error {
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

	pass := dag.SetSecret("password", dockerPassword)

	// push the images to the registry
	digest, err := dag.Container().
		WithRegistryAuth("docker.io", dockerUsername, pass).
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

func (d *Build) goCache() *CacheVolume {
	return dag.CacheVolume("go-cache")
}
