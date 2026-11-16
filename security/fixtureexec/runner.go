// Package fixtureexec runs disposable, no-network synthetic fixture commands.
// It is not wired to ARTEX, is not an authorization service, and is not an
// executor for customer data or production credentials. A trusted supervisor,
// independent egress and credential brokers, signed fixture inventory, durable
// leases, host isolation, and active-run revocation remain necessary.
package fixtureexec

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

const (
	fixtureAcknowledgement = "I_UNDERSTAND_DISPOSABLE_DOCKER_HOST_ONLY"
	fixturePath            = "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
	fixtureTmpfs           = "rw,nosuid,nodev,noexec,size=16777216,uid=65532,gid=65532"
	outputLimit            = 64 << 10
	cleanupTimeout         = 8 * time.Second
)

var imageIDPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
var containerIDPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
var ErrUnconfirmedStop = errors.New("fixture container stop or removal was not confirmed")
var ErrRunnerBusy = errors.New("fixture runner already has a live run")
var ErrUnsafeRuntime = errors.New("fixture Docker runtime or image did not meet the no-network contract")

type Result struct {
	// Reference is the generated Docker name, retained even if create has an
	// uncertain outcome so an independent supervisor can reconcile that name.
	Reference string
	// Output is bounded diagnostic output, not a durable or complete evidence
	// record. Attach interruptions and truncation require independent custody.
	Output          []byte
	OutputTruncated bool
	ExitCode        int
	// StopConfirmed is false after any uncertain create/stop/removal outcome.
	// A future durable supervisor must retain its reservation and reconcile the
	// Docker daemon before admitting another run when this is false.
	StopConfirmed bool
}

type dockerClient interface {
	call(context.Context, ...string) ([]byte, bool, error)
}

type Runner struct {
	docker         dockerClient
	imageID        string
	mu             sync.Mutex
	busy, poisoned bool
}

// begin admits one run per Runner instance. This is not a durable or cross-process
// lease; a future supervisor must bind it to the database reservation and recover
// orphaned containers before accepting work after a restart.
func (r *Runner) begin() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.poisoned {
		return ErrUnconfirmedStop
	}
	if r.busy {
		return ErrRunnerBusy
	}
	r.busy = true
	return nil
}

func (r *Runner) end(confirmed bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.busy = false
	if !confirmed {
		r.poisoned = true
	}
}

// NewSyntheticDocker requires an explicit disposable-host acknowledgement.
// This environment variable is an accident guard, not proof that the host,
// image, target data, daemon, or invoking principal is safe. dockerBinary and
// imageID must be provisioned by an independently trusted test operator, never
// supplied by an agent or customer. The binary is not mounted into the container.
func NewSyntheticDocker(dockerBinary, imageID string) (*Runner, error) {
	if os.Getenv("ARTEX_SYNTHETIC_DOCKER_TEST") != fixtureAcknowledgement || !filepath.IsAbs(dockerBinary) || !imageIDPattern.MatchString(imageID) {
		return nil, ErrUnsafeRuntime
	}
	info, err := os.Stat(dockerBinary)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o022 != 0 || info.Mode().Perm()&0o111 == 0 {
		return nil, ErrUnsafeRuntime
	}
	return &Runner{docker: localDocker{binary: dockerBinary}, imageID: imageID}, nil
}

type boundedOutput struct {
	mu        sync.Mutex
	buf       bytes.Buffer
	truncated bool
}

func (b *boundedOutput) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	n := len(p)
	remaining := outputLimit - b.buf.Len()
	if remaining > 0 {
		if len(p) > remaining {
			_, _ = b.buf.Write(p[:remaining])
		} else {
			_, _ = b.buf.Write(p)
		}
	}
	if len(p) > remaining {
		b.truncated = true
	}
	return n, nil
}

type localDocker struct{ binary string }

func (d localDocker) call(ctx context.Context, args ...string) ([]byte, bool, error) {
	cmd := exec.CommandContext(ctx, d.binary, args...)
	// Do not inherit host credentials, proxies, Docker context or environment.
	cmd.Env = []string{"PATH=/usr/bin:/bin", "HOME=/nonexistent", "DOCKER_CONFIG=/nonexistent"}
	cmd.Dir = "/"
	var out, stderr boundedOutput
	cmd.Stdout = &out
	cmd.Stderr = &stderr
	err := cmd.Run()
	if len(args) > 0 && args[0] == "start" {
		// Container output is useful to the fixture, but daemon warnings must
		// not be mixed into the JSON returned by inspect commands.
		var combined boundedOutput
		_, _ = combined.Write(out.buf.Bytes())
		_, _ = combined.Write(stderr.buf.Bytes())
		combined.truncated = combined.truncated || out.truncated || stderr.truncated
		return bytes.Clone(combined.buf.Bytes()), combined.truncated, err
	}
	return bytes.Clone(out.buf.Bytes()), out.truncated, err
}

type imageConfig struct {
	Env     []string                   `json:"Env"`
	Volumes map[string]json.RawMessage `json:"Volumes"`
}

type containerInfo struct {
	Name   string `json:"Name"`
	Image  string `json:"Image"`
	Config struct {
		User        string                     `json:"User"`
		Env         []string                   `json:"Env"`
		Entrypoint  []string                   `json:"Entrypoint"`
		Cmd         []string                   `json:"Cmd"`
		Tty         bool                       `json:"Tty"`
		OpenStdin   bool                       `json:"OpenStdin"`
		Labels      map[string]string          `json:"Labels"`
		Volumes     map[string]json.RawMessage `json:"Volumes"`
		Healthcheck *struct {
			Test []string `json:"Test"`
		} `json:"Healthcheck"`
	} `json:"Config"`
	HostConfig struct {
		NetworkMode                                                string `json:"NetworkMode"`
		IpcMode                                                    string `json:"IpcMode"`
		PidMode                                                    string `json:"PidMode"`
		UTSMode                                                    string `json:"UTSMode"`
		UsernsMode                                                 string `json:"UsernsMode"`
		CgroupnsMode                                               string `json:"CgroupnsMode"`
		Privileged                                                 bool   `json:"Privileged"`
		AutoRemove                                                 bool   `json:"AutoRemove"`
		ReadonlyRootfs                                             bool   `json:"ReadonlyRootfs"`
		CapAdd, CapDrop, SecurityOpt, Binds, VolumesFrom, GroupAdd []string
		DeviceCgroupRules, ExtraHosts                              []string
		Sysctls                                                    map[string]string
		Devices, DeviceRequests, Mounts                            []json.RawMessage
		Tmpfs                                                      map[string]string `json:"Tmpfs"`
		Memory                                                     int64             `json:"Memory"`
		MemorySwap                                                 int64             `json:"MemorySwap"`
		NanoCpus                                                   int64             `json:"NanoCpus"`
		PidsLimit                                                  *int64            `json:"PidsLimit"`
		LogConfig                                                  struct {
			Type string `json:"Type"`
		} `json:"LogConfig"`
		RestartPolicy struct {
			Name              string `json:"Name"`
			MaximumRetryCount int    `json:"MaximumRetryCount"`
		} `json:"RestartPolicy"`
	} `json:"HostConfig"`
	Mounts          []struct{ Type, Destination string } `json:"Mounts"`
	NetworkSettings struct {
		Networks map[string]json.RawMessage `json:"Networks"`
	} `json:"NetworkSettings"`
	State struct {
		Status                      string
		Running, Paused, Restarting bool
		ExitCode                    int
	} `json:"State"`
}

func safeEnvironment(env []string) bool {
	// The fixture image may contain only the standard non-secret PATH. An empty
	// list is also valid; the trusted fixture image must be inspected separately.
	return len(env) == 0 || (len(env) == 1 && env[0] == fixturePath)
}

func safeImage(raw []byte) bool {
	var cfg imageConfig
	return json.Unmarshal(raw, &cfg) == nil && len(cfg.Volumes) == 0 && safeEnvironment(cfg.Env)
}

func safeInfo(raw []byte, imageID, name, nonce, command string) bool {
	var c containerInfo
	if json.Unmarshal(raw, &c) != nil {
		return false
	}
	h := c.HostConfig
	if c.Name != "/"+name || c.Image != imageID || c.Config.User != "65532:65532" || !safeEnvironment(c.Config.Env) ||
		c.Config.Tty || c.Config.OpenStdin || len(c.Config.Volumes) != 0 || c.Config.Labels["io.artex.fixture.nonce"] != nonce ||
		len(c.Config.Entrypoint) != 1 || c.Config.Entrypoint[0] != "/bin/bash" ||
		len(c.Config.Cmd) != 2 || c.Config.Cmd[0] != "-c" || c.Config.Cmd[1] != command {
		return false
	}
	if c.Config.Healthcheck != nil && (len(c.Config.Healthcheck.Test) != 1 || c.Config.Healthcheck.Test[0] != "NONE") {
		return false
	}
	if h.NetworkMode != "none" || h.IpcMode != "none" || h.PidMode != "" || h.UTSMode == "host" || h.UsernsMode == "host" || h.CgroupnsMode != "private" ||
		h.Privileged || h.AutoRemove || !h.ReadonlyRootfs || len(h.CapAdd) != 0 || len(h.CapDrop) != 1 || h.CapDrop[0] != "ALL" ||
		len(h.SecurityOpt) != 1 || (h.SecurityOpt[0] != "no-new-privileges:true" && h.SecurityOpt[0] != "no-new-privileges") ||
		len(h.Binds) != 0 || len(h.VolumesFrom) != 0 || len(h.GroupAdd) != 0 || len(h.Devices) != 0 || len(h.DeviceRequests) != 0 || len(h.Mounts) != 0 ||
		len(h.DeviceCgroupRules) != 0 || len(h.ExtraHosts) != 0 || len(h.Sysctls) != 0 ||
		h.Memory != 268435456 || h.MemorySwap != 268435456 || h.NanoCpus != 500000000 || h.PidsLimit == nil || *h.PidsLimit != 64 || h.LogConfig.Type != "none" ||
		h.RestartPolicy.Name != "no" || h.RestartPolicy.MaximumRetryCount != 0 ||
		len(h.Tmpfs) != 1 || h.Tmpfs["/tmp"] != fixtureTmpfs {
		return false
	}
	for network := range c.NetworkSettings.Networks {
		if network != "none" {
			return false
		}
	}
	for _, m := range c.Mounts {
		if m.Type != "tmpfs" || m.Destination != "/tmp" {
			return false
		}
	}
	return c.State.Status == "created" && !c.State.Running && !c.State.Paused && !c.State.Restarting
}

func (r *Runner) callJSON(ctx context.Context, args ...string) ([]byte, error) {
	out, truncated, err := r.docker.call(ctx, args...)
	if err != nil || truncated {
		return nil, ErrUnsafeRuntime
	}
	return bytes.TrimSpace(out), nil
}

func (r *Runner) verifyDaemonAndImage(ctx context.Context) error {
	raw, err := r.callJSON(ctx, "info", "--format", "{{json .SecurityOptions}}")
	if err != nil {
		return err
	}
	var options []string
	if json.Unmarshal(raw, &options) != nil {
		return ErrUnsafeRuntime
	}
	seccomp := false
	for _, option := range options {
		if option == "name=seccomp,profile=builtin" || option == "name=seccomp,profile=default" {
			seccomp = true
		}
	}
	if !seccomp {
		return ErrUnsafeRuntime
	}
	raw, err = r.callJSON(ctx, "image", "inspect", "--format", "{{json .Config}}", r.imageID)
	if err != nil || !safeImage(raw) {
		return ErrUnsafeRuntime
	}
	return nil
}

// Run executes only in a fresh Docker container with no network, no host mounts,
// no inherited host environment, non-root UID, dropped capabilities, read-only
// root, default seccomp, no-new-privileges and strict resource limits. The image
// must be a preloaded immutable synthetic fixture image. No real credential or
// customer data may be present in the image, command or output. This method is
// deliberately not connected to any server route, agent, scheduler or DB lease.
func (r *Runner) Run(ctx context.Context, command string) (result Result, err error) {
	result.StopConfirmed = true // no create request has been sent yet
	if r == nil || r.docker == nil || !imageIDPattern.MatchString(r.imageID) || ctx == nil || !utf8.ValidString(command) || len(command) == 0 || len(command) > 4096 || strings.IndexByte(command, 0) >= 0 {
		return result, ErrUnsafeRuntime
	}
	if err := ctx.Err(); err != nil {
		return result, err
	}
	if err := r.begin(); err != nil {
		result.StopConfirmed = false
		return result, err
	}
	defer func() { r.end(result.StopConfirmed) }()
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	if err = r.verifyDaemonAndImage(ctx); err != nil {
		return result, err
	}
	var nonceBytes [16]byte
	if _, err = rand.Read(nonceBytes[:]); err != nil {
		return result, err
	}
	nonce := hex.EncodeToString(nonceBytes[:])
	name := "artex-fixture-" + nonce
	result.Reference = name
	args := []string{"create", "--name", name, "--label", "io.artex.fixture.nonce=" + nonce, "--pull=never",
		"--network=none", "--ipc=none", "--cgroupns=private", "--user=65532:65532", "--cap-drop=ALL",
		"--security-opt=no-new-privileges:true", "--read-only", "--pids-limit=64", "--memory=268435456", "--memory-swap=268435456", "--cpus=0.5", "--restart=no",
		"--tmpfs=/tmp:" + fixtureTmpfs, "--log-driver=none", "--no-healthcheck", "--entrypoint=/bin/bash", r.imageID, "-c", command}
	result.StopConfirmed = false
	created, truncated, createErr := r.docker.call(ctx, args...)
	id := strings.TrimSpace(string(created))
	if createErr != nil || truncated || !containerIDPattern.MatchString(id) {
		// The daemon may still finish an interrupted create. Never claim stop or
		// release a durable lease solely because the Docker client failed.
		return result, errors.Join(ErrUnconfirmedStop, createErr)
	}
	defer func() {
		confirmed, exitCode, cleanupErr := r.stopAndRemove(id, nonce)
		result.StopConfirmed = confirmed
		result.ExitCode = exitCode
		if !confirmed {
			err = errors.Join(err, ErrUnconfirmedStop, cleanupErr)
		} else if err == nil && exitCode != 0 {
			err = fmt.Errorf("fixture exited with status %d", exitCode)
		}
	}()
	inspect, inspectErr := r.callJSON(ctx, "container", "inspect", "--format", "{{json .}}", id)
	if inspectErr != nil || !safeInfo(inspect, r.imageID, name, nonce, command) {
		return result, ErrUnsafeRuntime
	}
	result.Output, result.OutputTruncated, err = r.docker.call(ctx, "start", "--attach", id)
	// Docker's exit status can be the container exit status. Always inspect and
	// remove the container with a fresh cleanup context before reporting stop.
	return result, err
}

func (r *Runner) stopAndRemove(id, nonce string) (bool, int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), cleanupTimeout)
	defer cancel()
	inspectState := func() (containerInfo, error) {
		raw, err := r.callJSON(ctx, "container", "inspect", "--format", "{{json .}}", id)
		if err != nil {
			return containerInfo{}, err
		}
		var info containerInfo
		if json.Unmarshal(raw, &info) != nil || info.Config.Labels["io.artex.fixture.nonce"] != nonce {
			return containerInfo{}, ErrUnsafeRuntime
		}
		return info, nil
	}
	state, err := inspectState()
	if err != nil {
		return false, 0, err
	}
	if state.State.Running || state.State.Paused || state.State.Restarting {
		_, _, killErr := r.docker.call(ctx, "kill", id)
		if killErr == nil {
			if _, _, err := r.docker.call(ctx, "wait", id); err != nil {
				return false, 0, err
			}
		}
		// The process may have exited between inspect and kill. Only a fresh
		// inspection can establish that; a failed kill alone proves nothing.
		state, err = inspectState()
		if err != nil {
			return false, 0, err
		}
		if killErr != nil && (state.State.Running || state.State.Paused || state.State.Restarting) {
			return false, 0, killErr
		}
	}
	if state.State.Running || state.State.Paused || state.State.Restarting || (state.State.Status != "created" && state.State.Status != "exited" && state.State.Status != "dead") {
		return false, 0, ErrUnconfirmedStop
	}
	if _, _, err := r.docker.call(ctx, "rm", id); err != nil {
		return false, 0, err
	}
	return true, state.State.ExitCode, nil
}
