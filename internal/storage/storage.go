package storage

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/aardsoft/tinydns-sidecar/internal/zone"
)

// Store is the persistence interface for zone data.
type Store interface {
	// ReadZone returns the ZoneFile for name, or a wrapped os.ErrNotExist if missing.
	ReadZone(name string) (*zone.ZoneFile, error)
	// WriteZone atomically persists z under name.
	WriteZone(name string, z zone.ZoneFile) error
	// DeleteZone removes the zone file for name.
	DeleteZone(name string) error

	// WriteRawData stores raw tinydns data for a key ID under raw/<keyID>.data.
	WriteRawData(keyID string, data []byte) error
	// ReadRawData returns the raw data for keyID, or wrapped os.ErrNotExist.
	ReadRawData(keyID string) ([]byte, error)
	// DeleteRawData removes the raw data file for keyID.
	DeleteRawData(keyID string) error
}

// FileStore implements Store using the local filesystem.
// Zone files are stored as {zonesDir}/{name}.yml.
// Raw data files are stored as {zonesDir}/raw/{keyID}.data.
type FileStore struct {
	zonesDir       string
	rebuildCommand string
	// zoneMu guards per-zone PATCH operations to prevent TOCTOU races.
	zoneMu sync.Map // map[string]*sync.Mutex
}

// NewFileStore creates a FileStore for the given zones directory.
// It creates the directory (and raw/ subdirectory) if they do not exist.
func NewFileStore(zonesDir, rebuildCommand string) (*FileStore, error) {
	if err := os.MkdirAll(zonesDir, 0o755); err != nil {
		return nil, fmt.Errorf("creating zones dir %s: %w", zonesDir, err)
	}
	rawDir := filepath.Join(zonesDir, "raw")
	if err := os.MkdirAll(rawDir, 0o755); err != nil {
		return nil, fmt.Errorf("creating raw dir %s: %w", rawDir, err)
	}
	return &FileStore{zonesDir: zonesDir, rebuildCommand: rebuildCommand}, nil
}

// zonePath returns the YAML file path for a zone name.
func (fs *FileStore) zonePath(name string) string {
	return filepath.Join(fs.zonesDir, name+".yml")
}

// rawPath returns the raw data file path for a key ID.
func (fs *FileStore) rawPath(keyID string) string {
	return filepath.Join(fs.zonesDir, "raw", keyID+".data")
}

// lockZone returns (and lazily creates) the per-zone mutex.
func (fs *FileStore) lockZone(name string) *sync.Mutex {
	v, _ := fs.zoneMu.LoadOrStore(name, &sync.Mutex{})
	return v.(*sync.Mutex)
}

// ReadZone reads and parses the YAML zone file for name.
func (fs *FileStore) ReadZone(name string) (*zone.ZoneFile, error) {
	data, err := os.ReadFile(fs.zonePath(name))
	if err != nil {
		return nil, err // caller checks os.ErrNotExist
	}
	var z zone.ZoneFile
	if err := yaml.Unmarshal(data, &z); err != nil {
		return nil, fmt.Errorf("parsing zone %s: %w", name, err)
	}
	return &z, nil
}

// WriteZone atomically writes z to disk and optionally triggers a rebuild.
// It acquires the per-zone lock to serialise concurrent PATCH operations.
func (fs *FileStore) WriteZone(name string, z zone.ZoneFile) error {
	mu := fs.lockZone(name)
	mu.Lock()
	defer mu.Unlock()

	return fs.writeZoneLocked(name, z)
}

func (fs *FileStore) writeZoneLocked(name string, z zone.ZoneFile) error {
	data, err := yaml.Marshal(z)
	if err != nil {
		return fmt.Errorf("marshalling zone %s: %w", name, err)
	}

	tmp := fs.zonePath(name) + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return fmt.Errorf("writing temp file: %w", err)
	}
	if err := os.Rename(tmp, fs.zonePath(name)); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("renaming zone file: %w", err)
	}

	fs.runRebuild()
	return nil
}

// DeleteZone removes the zone file for name.
func (fs *FileStore) DeleteZone(name string) error {
	mu := fs.lockZone(name)
	mu.Lock()
	defer mu.Unlock()

	if err := os.Remove(fs.zonePath(name)); err != nil {
		return err
	}
	fs.runRebuild()
	return nil
}

// WriteRawData atomically stores raw tinydns data for keyID.
func (fs *FileStore) WriteRawData(keyID string, data []byte) error {
	tmp := fs.rawPath(keyID) + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return fmt.Errorf("writing raw temp file: %w", err)
	}
	if err := os.Rename(tmp, fs.rawPath(keyID)); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("renaming raw data file: %w", err)
	}
	fs.runRebuild()
	return nil
}

// ReadRawData returns the raw data bytes for keyID.
func (fs *FileStore) ReadRawData(keyID string) ([]byte, error) {
	return os.ReadFile(fs.rawPath(keyID))
}

// DeleteRawData removes the raw data file for keyID.
func (fs *FileStore) DeleteRawData(keyID string) error {
	if err := os.Remove(fs.rawPath(keyID)); err != nil {
		return err
	}
	fs.runRebuild()
	return nil
}

// runRebuild executes the configured rebuild command (if any).
// It runs asynchronously and logs output; a non-zero exit is a warning only.
func (fs *FileStore) runRebuild() {
	if fs.rebuildCommand == "" {
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		cmd := exec.CommandContext(ctx, "sh", "-c", fs.rebuildCommand)
		var out bytes.Buffer
		cmd.Stdout = &out
		cmd.Stderr = &out

		err := cmd.Run()
		if err != nil {
			slog.Warn("rebuild command failed",
				"command", fs.rebuildCommand,
				"error", err,
				"output", out.String())
		} else {
			slog.Info("rebuild command succeeded",
				"command", fs.rebuildCommand,
				"output", out.String())
		}
	}()
}
