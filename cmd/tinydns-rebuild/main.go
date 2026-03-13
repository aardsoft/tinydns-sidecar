// tinydns-rebuild — aggregate raw tinydns data files and rebuild data.cdb.
//
// Intended to run inside the tinydns container alongside the tinydns daemon.
// It watches the raw/ subdirectory of zones_dir (written by tinydns-sidecar)
// for changes and, when any file changes, concatenates all *.data files into
// a single data file and runs tinydns-data to compile data.cdb.
//
// After a successful local rebuild it optionally distributes the data file to
// remote nameservers via SSH and triggers tinydns-data there too.
//
// Usage:
//
//	tinydns-rebuild [-config path] [-once]
//
// Flags:
//
//	-config   path to config file (env: TINYDNS_REBUILD_CONFIG,
//	          default: /etc/tinydns-sidecar/rebuild.yml)
//	-once     run a single rebuild and exit; do not poll
package main

import (
	"bytes"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	// ZonesDir is the directory written by tinydns-sidecar.
	// Raw data files are read from ZonesDir/raw/*.data.
	ZonesDir string `yaml:"zones_dir"`

	// DataFile is the assembled output written before running DataCommand.
	DataFile string `yaml:"data_file"`

	// DataCommand is the command run (via sh -c) to compile data.cdb from
	// DataFile.  It is executed in the directory containing DataFile.
	// Defaults to "tinydns-data".
	DataCommand string `yaml:"data_command"`

	// PollInterval is how often (in seconds) the raw/ directory is checked
	// for changes.  Defaults to 5.
	PollInterval int `yaml:"poll_interval"`

	// Debug enables verbose logging of the exact commands and environment
	// variables used during sync and remote operations.
	Debug bool `yaml:"debug,omitempty"`

	// Remotes lists remote nameservers to update after a successful local
	// rebuild.  Requires ssh and scp to be available in $PATH.
	Remotes []RemoteConfig `yaml:"remotes,omitempty"`
}

type RemoteConfig struct {
	// Host is the SSH hostname or IP.
	Host string `yaml:"host"`
	// User is the SSH login user (default: current user).
	User string `yaml:"user,omitempty"`
	// KeyFile is the path to the SSH private key.
	KeyFile string `yaml:"key_file,omitempty"`
	// DataDir is the directory on the remote host that contains the data file
	// and where tinydns-data will be run.
	DataDir string `yaml:"data_dir"`
	// DataCommand overrides the top-level DataCommand for this remote.
	DataCommand string `yaml:"data_command,omitempty"`
	// SyncCommand overrides the default scp-based file transfer when set.
	// Executed via sh -c. Accepts a single command or a multiline YAML block.
	// Available environment variables: TINYDNS_DATA_FILE, TINYDNS_REMOTE_HOST,
	// TINYDNS_REMOTE_USER, TINYDNS_REMOTE_KEY_FILE, TINYDNS_REMOTE_DATA_DIR,
	// TINYDNS_REMOTE_DATA_COMMAND.
	SyncCommand string `yaml:"sync_command,omitempty"`
	// RemoteCommand overrides the default ssh-invoked tinydns-data rebuild when
	// set.  Executed via sh -c.  Same environment variables as SyncCommand.
	RemoteCommand string `yaml:"remote_command,omitempty"`
}

func loadConfig(path string) (*Config, error) {
	if path == "" {
		path = os.Getenv("TINYDNS_REBUILD_CONFIG")
	}
	if path == "" {
		path = "/etc/tinydns-sidecar/rebuild.yml"
	}

	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("opening config %s: %w", path, err)
	}
	defer f.Close()

	cfg := &Config{}
	dec := yaml.NewDecoder(f)
	dec.KnownFields(true)
	if err := dec.Decode(cfg); err != nil {
		return nil, fmt.Errorf("parsing config %s: %w", path, err)
	}

	if cfg.DataCommand == "" {
		cfg.DataCommand = "tinydns-data"
	}
	if cfg.PollInterval <= 0 {
		cfg.PollInterval = 5
	}

	return cfg, nil
}

func main() {
	slogOpts := &slog.HandlerOptions{
		ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			if a.Key == slog.MessageKey && len(groups) == 0 {
				return slog.String("_msg", a.Value.String())
			}
			return a
		},
	}
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, slogOpts)))

	cfgPath := flag.String("config", os.Getenv("TINYDNS_REBUILD_CONFIG"), "path to config file (env: TINYDNS_REBUILD_CONFIG)")
	once := flag.Bool("once", false, "run a single rebuild then exit")
	debug := flag.Bool("debug", false, "log exact commands and env vars for sync/remote operations")
	flag.Parse()

	cfg, err := loadConfig(*cfgPath)
	if err != nil {
		slog.Error("loading config", "error", err)
		os.Exit(1)
	}
	if *debug {
		cfg.Debug = true
	}

	if *once {
		if err := rebuild(cfg); err != nil {
			slog.Error("rebuild failed", "error", err)
			os.Exit(1)
		}
		return
	}

	slog.Info("starting poll loop",
		"zones_dir", cfg.ZonesDir,
		"data_file", cfg.DataFile,
		"poll_interval_s", cfg.PollInterval,
	)

	var lastMod time.Time
	ticker := time.NewTicker(time.Duration(cfg.PollInterval) * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		mod, err := latestMod(cfg.ZonesDir)
		if err != nil {
			slog.Warn("checking raw dir", "error", err)
			continue
		}
		if mod.IsZero() || !mod.After(lastMod) {
			continue
		}
		slog.Info("change detected", "latest_mod", mod)
		if err := rebuild(cfg); err != nil {
			slog.Error("rebuild failed", "error", err)
			continue
		}
		lastMod = mod
	}
}

// latestMod returns the most recent modification time among all *.data files
// in ZonesDir/raw/.  Returns zero time if the directory is empty or absent.
func latestMod(zonesDir string) (time.Time, error) {
	pattern := filepath.Join(zonesDir, "raw", "*.data")
	files, err := filepath.Glob(pattern)
	if err != nil {
		return time.Time{}, err
	}
	var latest time.Time
	for _, f := range files {
		fi, err := os.Stat(f)
		if err != nil {
			continue
		}
		if fi.ModTime().After(latest) {
			latest = fi.ModTime()
		}
	}
	return latest, nil
}

// rebuild assembles the data file and runs tinydns-data locally, then
// distributes to any configured remotes.
func rebuild(cfg *Config) error {
	if err := assemble(cfg); err != nil {
		return fmt.Errorf("assembling data file: %w", err)
	}
	if err := runDataCommand(filepath.Dir(cfg.DataFile), cfg.DataCommand); err != nil {
		return fmt.Errorf("running %s: %w", cfg.DataCommand, err)
	}
	slog.Info("local rebuild complete", "data_file", cfg.DataFile)

	for _, r := range cfg.Remotes {
		if err := distribute(cfg, r); err != nil {
			// Log but continue — a failed remote should not block the others.
			slog.Error("distributing to remote", "host", r.Host, "error", err)
		}
	}
	return nil
}

// assemble concatenates all raw/*.data files into cfg.DataFile in sorted order.
func assemble(cfg *Config) error {
	pattern := filepath.Join(cfg.ZonesDir, "raw", "*.data")
	files, err := filepath.Glob(pattern)
	if err != nil {
		return err
	}
	sort.Strings(files)

	var buf bytes.Buffer
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			return fmt.Errorf("reading %s: %w", f, err)
		}
		buf.Write(data)
		// Ensure each file ends with a newline so records don't run together.
		if len(data) > 0 && data[len(data)-1] != '\n' {
			buf.WriteByte('\n')
		}
	}

	if err := os.MkdirAll(filepath.Dir(cfg.DataFile), 0o755); err != nil {
		return fmt.Errorf("creating data dir: %w", err)
	}
	if err := os.WriteFile(cfg.DataFile, buf.Bytes(), 0o644); err != nil {
		return fmt.Errorf("writing %s: %w", cfg.DataFile, err)
	}
	slog.Info("assembled data file", "files", len(files), "bytes", buf.Len())
	return nil
}

// runDataCommand executes the data compilation command in dir.
func runDataCommand(dir, command string) error {
	cmd := exec.Command("sh", "-c", command)
	cmd.Dir = dir
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%w; output: %s", err, out.String())
	}
	if out.Len() > 0 {
		slog.Info("data command output", "output", out.String())
	}
	return nil
}

// runShellCommand executes script via sh -c with extra appended to the process
// environment.  Returns combined stdout+stderr output and any error.
func runShellCommand(script string, extra []string, debug bool) (string, error) {
	if debug {
		slog.Info("shell command", "script", script, "env", extra)
	}
	cmd := exec.Command("sh", "-c", script)
	cmd.Env = append(os.Environ(), extra...)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	err := cmd.Run()
	return out.String(), err
}

// distribute copies the assembled data file to a remote host and runs
// tinydns-data there.  Requires ssh and scp in $PATH unless sync_command /
// remote_command overrides are configured.
func distribute(cfg *Config, r RemoteConfig) error {
	target := r.Host
	if r.User != "" {
		target = r.User + "@" + r.Host
	}

	dataCmd := r.DataCommand
	if dataCmd == "" {
		dataCmd = cfg.DataCommand
	}

	// Environment variables available to sync_command and remote_command.
	env := []string{
		"TINYDNS_DATA_FILE=" + cfg.DataFile,
		"TINYDNS_REMOTE_HOST=" + r.Host,
		"TINYDNS_REMOTE_USER=" + r.User,
		"TINYDNS_REMOTE_KEY_FILE=" + r.KeyFile,
		"TINYDNS_REMOTE_DATA_DIR=" + r.DataDir,
		"TINYDNS_REMOTE_DATA_COMMAND=" + dataCmd,
	}

	sshArgs := []string{"-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=accept-new"}
	if r.KeyFile != "" {
		sshArgs = append(sshArgs, "-i", r.KeyFile)
	}

	// Push the data file.
	if r.SyncCommand != "" {
		out, err := runShellCommand(r.SyncCommand, env, cfg.Debug)
		if err != nil {
			return fmt.Errorf("sync_command to %s: %w; output: %s", r.Host, err, out)
		}
		if out != "" {
			slog.Info("sync command output", "host", r.Host, "output", out)
		}
	} else {
		remotePath := target + ":" + filepath.Join(r.DataDir, filepath.Base(cfg.DataFile))
		scpArgs := append(append([]string{}, sshArgs...), cfg.DataFile, remotePath)
		if cfg.Debug {
			slog.Info("scp command", "args", append([]string{"scp"}, scpArgs...))
		}
		scpCmd := exec.Command("scp", scpArgs...)
		var scpOut bytes.Buffer
		scpCmd.Stdout = &scpOut
		scpCmd.Stderr = &scpOut
		if err := scpCmd.Run(); err != nil {
			return fmt.Errorf("scp to %s: %w; output: %s", r.Host, err, scpOut.String())
		}
	}

	// Run tinydns-data on the remote.
	if r.RemoteCommand != "" {
		out, err := runShellCommand(r.RemoteCommand, env, cfg.Debug)
		if err != nil {
			return fmt.Errorf("remote_command on %s: %w; output: %s", r.Host, err, out)
		}
		if out != "" {
			slog.Info("remote command output", "host", r.Host, "output", out)
		}
	} else {
		remoteCmd := fmt.Sprintf("cd %s && %s", r.DataDir, dataCmd)
		sshRunArgs := append(append([]string{}, sshArgs...), target, remoteCmd)
		if cfg.Debug {
			slog.Info("ssh command", "args", append([]string{"ssh"}, sshRunArgs...))
		}
		sshCmd := exec.Command("ssh", sshRunArgs...)
		var sshOut bytes.Buffer
		sshCmd.Stdout = &sshOut
		sshCmd.Stderr = &sshOut
		if err := sshCmd.Run(); err != nil {
			return fmt.Errorf("ssh %s %q: %w; output: %s", r.Host, remoteCmd, err, sshOut.String())
		}
	}

	slog.Info("remote rebuild complete", "host", r.Host)
	return nil
}
