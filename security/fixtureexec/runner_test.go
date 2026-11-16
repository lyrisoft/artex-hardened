package fixtureexec

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const fixtureImageID = "sha256:" + "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
const fixtureContainerID = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

type fakeDocker struct {
	calls                                                                            [][]string
	name, nonce, command                                                             string
	state                                                                            string
	exitCode                                                                         int
	imageEnv                                                                         []string
	imageVolumes                                                                     map[string]json.RawMessage
	noSeccomp, createFailure, killFailure, removeFailure, inspectFailure, blockStart bool
	mutate                                                                           func(*containerInfo)
	started                                                                          chan struct{}
}

func (f *fakeDocker) call(ctx context.Context, args ...string) ([]byte, bool, error) {
	f.calls = append(f.calls, append([]string(nil), args...))
	switch args[0] {
	case "info":
		if f.noSeccomp {
			return []byte(`[]`), false, nil
		}
		return []byte(`["name=seccomp,profile=builtin"]`), false, nil
	case "image":
		raw, _ := json.Marshal(imageConfig{Env: f.imageEnv, Volumes: f.imageVolumes})
		return raw, false, nil
	case "create":
		if f.createFailure {
			return nil, false, errors.New("uncertain create")
		}
		for i := range args {
			if args[i] == "--name" && i+1 < len(args) {
				f.name = args[i+1]
			}
			if args[i] == "--label" && i+1 < len(args) {
				f.nonce = strings.TrimPrefix(args[i+1], "io.artex.fixture.nonce=")
			}
		}
		f.command = args[len(args)-1]
		f.state = "created"
		return []byte(fixtureContainerID + "\n"), false, nil
	case "container":
		if f.inspectFailure {
			return nil, false, errors.New("inspect unavailable")
		}
		info := f.info()
		if f.mutate != nil && f.state == "created" {
			f.mutate(&info)
		}
		raw, _ := json.Marshal(info)
		return raw, false, nil
	case "start":
		if f.blockStart {
			f.state = "running"
			if f.started != nil {
				close(f.started)
			}
			<-ctx.Done()
			return nil, false, ctx.Err()
		}
		f.state = "exited"
		return []byte("synthetic output"), false, nil
	case "kill":
		if f.killFailure {
			return nil, false, errors.New("kill unavailable")
		}
		f.state = "exited"
		f.exitCode = 137
		return nil, false, nil
	case "wait":
		return []byte("137\n"), false, nil
	case "rm":
		if f.removeFailure {
			return nil, false, errors.New("remove unavailable")
		}
		f.state = "removed"
		return nil, false, nil
	default:
		return nil, false, errors.New("unexpected Docker call")
	}
}

func (f *fakeDocker) info() containerInfo {
	var c containerInfo
	c.Name = "/" + f.name
	c.Image = fixtureImageID
	c.Config.User = "65532:65532"
	c.Config.Env = []string{fixturePath}
	c.Config.Entrypoint = []string{"/bin/bash"}
	c.Config.Cmd = []string{"-c", f.command}
	c.Config.Labels = map[string]string{"io.artex.fixture.nonce": f.nonce}
	c.HostConfig.NetworkMode = "none"
	c.HostConfig.IpcMode = "none"
	c.HostConfig.CgroupnsMode = "private"
	c.HostConfig.ReadonlyRootfs = true
	c.HostConfig.CapDrop = []string{"ALL"}
	c.HostConfig.SecurityOpt = []string{"no-new-privileges:true"}
	c.HostConfig.Tmpfs = map[string]string{"/tmp": fixtureTmpfs}
	c.HostConfig.Memory = 268435456
	c.HostConfig.MemorySwap = 268435456
	c.HostConfig.RestartPolicy.Name = "no"
	c.HostConfig.NanoCpus = 500000000
	pids := int64(64)
	c.HostConfig.PidsLimit = &pids
	c.HostConfig.LogConfig.Type = "none"
	c.State.Status = f.state
	c.State.Running = f.state == "running"
	c.State.ExitCode = f.exitCode
	return c
}
func (f *fakeDocker) called(name string) bool {
	for _, c := range f.calls {
		if len(c) > 0 && c[0] == name {
			return true
		}
	}
	return false
}

func TestFixtureRunnerUsesNoNetworkAndConfirmsStop(t *testing.T) {
	docker := &fakeDocker{}
	r := &Runner{docker: docker, imageID: fixtureImageID}
	command := `printf '%s' 'synthetic; $(not-a-host-command)'`
	got, err := r.Run(context.Background(), command)
	if err != nil || !got.StopConfirmed || got.ExitCode != 0 || string(got.Output) != "synthetic output" || docker.state != "removed" {
		t.Fatalf("result=%+v err=%v state=%q", got, err, docker.state)
	}
	var create []string
	for _, c := range docker.calls {
		if c[0] == "create" {
			create = c
		}
	}
	joined := strings.Join(create, "\x00")
	for _, arg := range []string{"--network=none", "--ipc=none", "--cgroupns=private", "--user=65532:65532", "--cap-drop=ALL", "--security-opt=no-new-privileges:true", "--read-only", "--pids-limit=64", "--memory=268435456", "--memory-swap=268435456", "--cpus=0.5", "--restart=no", "--log-driver=none", "--no-healthcheck", "--entrypoint=/bin/bash", fixtureImageID, "-c", command} {
		if !strings.Contains("\x00"+joined+"\x00", "\x00"+arg+"\x00") {
			t.Fatalf("create missing %q", arg)
		}
	}
	for _, arg := range create {
		if arg == "--privileged" || arg == "--env" || arg == "-v" || arg == "--mount" {
			t.Fatalf("unsafe Docker argument %q", arg)
		}
	}
}

func TestFixtureRunnerRejectsUnsafeRuntimeBeforeStart(t *testing.T) {
	tests := []struct {
		name   string
		change func(*fakeDocker)
	}{
		{"missing seccomp", func(f *fakeDocker) { f.noSeccomp = true }},
		{"image secret environment", func(f *fakeDocker) { f.imageEnv = []string{"SECRET=synthetic"} }},
		{"image volume", func(f *fakeDocker) { f.imageVolumes = map[string]json.RawMessage{"/data": json.RawMessage(`{}`)} }},
		{"host network", func(f *fakeDocker) { f.mutate = func(c *containerInfo) { c.HostConfig.NetworkMode = "host" } }},
		{"attached network", func(f *fakeDocker) {
			f.mutate = func(c *containerInfo) {
				c.NetworkSettings.Networks = map[string]json.RawMessage{"bridge": json.RawMessage(`{}`)}
			}
		}},
		{"host uts", func(f *fakeDocker) { f.mutate = func(c *containerInfo) { c.HostConfig.UTSMode = "host" } }},
		{"sysctl", func(f *fakeDocker) {
			f.mutate = func(c *containerInfo) { c.HostConfig.Sysctls = map[string]string{"net.ipv4.ip_forward": "1"} }
		}},
		{"root", func(f *fakeDocker) { f.mutate = func(c *containerInfo) { c.Config.User = "0:0" } }},
		{"host mount", func(f *fakeDocker) {
			f.mutate = func(c *containerInfo) { c.HostConfig.Binds = []string{"/host:/host"} }
		}},
		{"privileged", func(f *fakeDocker) { f.mutate = func(c *containerInfo) { c.HostConfig.Privileged = true } }},
		{"writable root", func(f *fakeDocker) { f.mutate = func(c *containerInfo) { c.HostConfig.ReadonlyRootfs = false } }},
		{"extra capability", func(f *fakeDocker) { f.mutate = func(c *containerInfo) { c.HostConfig.CapAdd = []string{"NET_ADMIN"} } }},
		{"unconfined seccomp", func(f *fakeDocker) {
			f.mutate = func(c *containerInfo) { c.HostConfig.SecurityOpt = []string{"seccomp=unconfined"} }
		}},
		{"image mismatch", func(f *fakeDocker) {
			f.mutate = func(c *containerInfo) { c.Image = "sha256:" + strings.Repeat("c", 64) }
		}},
		{"pids unbounded", func(f *fakeDocker) { f.mutate = func(c *containerInfo) { c.HostConfig.PidsLimit = nil } }},
		{"host logging", func(f *fakeDocker) { f.mutate = func(c *containerInfo) { c.HostConfig.LogConfig.Type = "json-file" } }},
		{"automatic restart", func(f *fakeDocker) { f.mutate = func(c *containerInfo) { c.HostConfig.RestartPolicy.Name = "always" } }},
		{"unbounded swap", func(f *fakeDocker) { f.mutate = func(c *containerInfo) { c.HostConfig.MemorySwap = -1 } }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			docker := &fakeDocker{}
			tc.change(docker)
			r := &Runner{docker: docker, imageID: fixtureImageID}
			got, err := r.Run(context.Background(), "echo fixture")
			if !errors.Is(err, ErrUnsafeRuntime) || docker.called("start") || !got.StopConfirmed {
				t.Fatalf("result=%+v err=%v calls=%v", got, err, docker.calls)
			}
		})
	}
}

func TestFixtureRunnerCancellationStopsOrRetainsUnconfirmed(t *testing.T) {
	for _, tc := range []struct {
		name      string
		killFails bool
	}{{"confirmed", false}, {"unconfirmed", true}} {
		t.Run(tc.name, func(t *testing.T) {
			docker := &fakeDocker{blockStart: true, killFailure: tc.killFails}
			r := &Runner{docker: docker, imageID: fixtureImageID}
			ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
			defer cancel()
			got, err := r.Run(ctx, "sleep 30")
			if err == nil || got.StopConfirmed == tc.killFails {
				t.Fatalf("result=%+v err=%v calls=%v", got, err, docker.calls)
			}
			if tc.killFails && !errors.Is(err, ErrUnconfirmedStop) {
				t.Fatalf("unconfirmed stop not surfaced: %v", err)
			}
			if tc.killFails {
				calls := len(docker.calls)
				next, nextErr := r.Run(context.Background(), "echo fixture")
				if next.StopConfirmed || !errors.Is(nextErr, ErrUnconfirmedStop) || len(docker.calls) != calls {
					t.Fatalf("unconfirmed cleanup allowed another run: %+v err=%v", next, nextErr)
				}
			}
			if !tc.killFails && (!docker.called("kill") || !docker.called("wait") || !docker.called("rm")) {
				t.Fatalf("cleanup missing: %v", docker.calls)
			}
		})
	}
}

func TestFixtureRunnerUncertainCreateAndRemoveFailClosed(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*fakeDocker)
	}{
		{"create", func(f *fakeDocker) { f.createFailure = true }},
		{"remove", func(f *fakeDocker) { f.removeFailure = true }},
		{"inspect", func(f *fakeDocker) { f.inspectFailure = true }},
		{"foreign label", func(f *fakeDocker) {
			f.mutate = func(c *containerInfo) { c.Config.Labels["io.artex.fixture.nonce"] = "other" }
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			docker := &fakeDocker{}
			tc.change(docker)
			got, err := (&Runner{docker: docker, imageID: fixtureImageID}).Run(context.Background(), "echo fixture")
			if got.StopConfirmed || !errors.Is(err, ErrUnconfirmedStop) {
				t.Fatalf("result=%+v err=%v", got, err)
			}
		})
	}
}

func TestFixtureRunnerInputAndOutputBounds(t *testing.T) {
	for _, command := range []string{"", strings.Repeat("x", 4097), "bad\x00command", string([]byte{0xff})} {
		docker := &fakeDocker{}
		got, err := (&Runner{docker: docker, imageID: fixtureImageID}).Run(context.Background(), command)
		if !errors.Is(err, ErrUnsafeRuntime) || !got.StopConfirmed || len(docker.calls) != 0 {
			t.Fatalf("invalid input accepted: err=%v", err)
		}
	}
	var out boundedOutput
	source := bytes.Repeat([]byte{'x'}, outputLimit+1234)
	n, err := out.Write(source)
	if err != nil || n != len(source) || out.buf.Len() != outputLimit || !out.truncated {
		t.Fatalf("bounded output n=%d err=%v len=%d", n, err, out.buf.Len())
	}
}

// Runs only from the disposable GitHub Docker fixture, after its positive-control
// target is listening. No ARTEX agent, customer data or real credentials are used.
func TestDockerNoNetworkSyntheticFixture(t *testing.T) {
	if os.Getenv("ARTEX_SYNTHETIC_DOCKER_TEST") != fixtureAcknowledgement {
		t.Skip("requires explicitly acknowledged disposable Docker fixture")
	}
	image := os.Getenv("ARTEX_FIXTURE_IMAGE_ID")
	binary, err := exec.LookPath("docker")
	if err != nil {
		t.Fatal(err)
	}
	r, err := NewSyntheticDocker(binary, image)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("ARTEX_SYNTHETIC_DUMMY_CANARY", "fixture-only-canary")
	command := `set -eu
      test "$(id -u)" = 65532
      test -z "${ARTEX_SYNTHETIC_DUMMY_CANARY+x}"
      grep -Eq '^NoNewPrivs:[[:space:]]+1$' /proc/self/status
      grep -Eq '^CapEff:[[:space:]]+0000000000000000$' /proc/self/status
      grep -Eq '^Seccomp:[[:space:]]+2$' /proc/self/status
      test ! -S /var/run/docker.sock
      touch /tmp/fixture-writable && rm /tmp/fixture-writable
      command -v unshare >/dev/null && unshare --help >/dev/null
      command -v curl >/dev/null && curl --version >/dev/null
      if unshare -Ur true >/dev/null 2>&1; then exit 1; fi
      if curl --noproxy '*' --connect-timeout 2 --max-time 4 -fsS http://172.30.139.20:80/ >/dev/null 2>&1; then exit 1; fi
      printf 'fixture-denied-network'`
	got, err := r.Run(context.Background(), command)
	if err != nil || !got.StopConfirmed || got.ExitCode != 0 || !bytes.Contains(got.Output, []byte("fixture-denied-network")) {
		t.Fatalf("result=%+v err=%v", got, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	type runResult struct {
		result Result
		err    error
	}
	done := make(chan runResult, 1)
	go func() { result, err := r.Run(ctx, "sleep 30"); done <- runResult{result, err} }()
	deadline := time.NewTimer(15 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		cmd := exec.Command(binary, "ps", "-q", "--filter", "label=io.artex.fixture.nonce")
		out, err := cmd.Output()
		if err != nil {
			cancel()
			t.Fatal(err)
		}
		if len(bytes.TrimSpace(out)) > 0 {
			break
		}
		select {
		case result := <-done:
			t.Fatalf("fixture exited before cancellation: %+v err=%v", result.result, result.err)
		case <-ticker.C:
		case <-deadline.C:
			cancel()
			t.Fatal("fixture did not start")
		}
	}
	cancel()
	select {
	case finished := <-done:
		got, err = finished.result, finished.err
	case <-time.After(15 * time.Second):
		t.Fatal("fixture did not stop after cancellation")
	}
	if err == nil || !got.StopConfirmed {
		t.Fatalf("cancel result=%+v err=%v", got, err)
	}
	cmd := exec.Command(binary, "ps", "-aq", "--filter", "label=io.artex.fixture.nonce")
	out, err := cmd.Output()
	if err != nil || len(bytes.TrimSpace(out)) != 0 {
		t.Fatalf("fixture containers remained: %q err=%v", out, err)
	}
}

func TestFixtureRunnerRejectsConcurrentAndUnconfirmedRuns(t *testing.T) {
	t.Run("concurrent", func(t *testing.T) {
		docker := &fakeDocker{blockStart: true, started: make(chan struct{})}
		r := &Runner{docker: docker, imageID: fixtureImageID}
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() { _, err := r.Run(ctx, "sleep 30"); done <- err }()
		select {
		case <-docker.started:
		case <-time.After(5 * time.Second):
			cancel()
			t.Fatal("first run did not start")
		}
		second, err := r.Run(context.Background(), "echo fixture")
		if !errors.Is(err, ErrRunnerBusy) || second.StopConfirmed {
			cancel()
			t.Fatalf("concurrent run accepted: %+v err=%v", second, err)
		}
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("first run did not stop")
		}
	})
	t.Run("uncertain_create_poisoned", func(t *testing.T) {
		docker := &fakeDocker{createFailure: true}
		r := &Runner{docker: docker, imageID: fixtureImageID}
		first, err := r.Run(context.Background(), "echo fixture")
		if first.StopConfirmed || !errors.Is(err, ErrUnconfirmedStop) {
			t.Fatalf("first result=%+v err=%v", first, err)
		}
		calls := len(docker.calls)
		docker.createFailure = false
		next, err := r.Run(context.Background(), "echo fixture")
		if next.StopConfirmed || !errors.Is(err, ErrUnconfirmedStop) || len(docker.calls) != calls {
			t.Fatalf("poisoned runner accepted a new run: %+v err=%v", next, err)
		}
	})
}

func TestSyntheticDockerConstructorRequiresAcknowledgement(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("ARTEX_SYNTHETIC_DOCKER_TEST", "")
	if _, err := NewSyntheticDocker(executable, fixtureImageID); !errors.Is(err, ErrUnsafeRuntime) {
		t.Fatalf("unacknowledged constructor: %v", err)
	}
	t.Setenv("ARTEX_SYNTHETIC_DOCKER_TEST", fixtureAcknowledgement)
	if _, err := NewSyntheticDocker("docker", fixtureImageID); !errors.Is(err, ErrUnsafeRuntime) {
		t.Fatalf("relative binary accepted: %v", err)
	}
	if _, err := NewSyntheticDocker(executable, "latest"); !errors.Is(err, ErrUnsafeRuntime) {
		t.Fatalf("mutable image accepted: %v", err)
	}
}

func TestLocalDockerClientDoesNotInheritHostEnvironment(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fake-docker")
	script := "#!/bin/sh\nif [ -n \"${ARTEX_FIXTURE_HOST_CANARY+x}\" ]; then printf leaked; else printf clean; fi\nprintf warning >&2\n"
	if err := os.WriteFile(path, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ARTEX_FIXTURE_HOST_CANARY", "synthetic-canary")
	client := localDocker{binary: path}
	out, truncated, err := client.call(context.Background(), "info")
	if err != nil || truncated || string(out) != "clean" {
		t.Fatalf("inspect output=%q truncated=%v err=%v", out, truncated, err)
	}
	out, truncated, err = client.call(context.Background(), "start")
	if err != nil || truncated || string(out) != "cleanwarning" {
		t.Fatalf("start output=%q truncated=%v err=%v", out, truncated, err)
	}
}
