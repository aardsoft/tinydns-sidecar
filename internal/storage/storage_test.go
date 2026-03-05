package storage

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/aardsoft/tinydns-sidecar/internal/zone"
)

func newTestStore(t *testing.T) *FileStore {
	t.Helper()
	dir := t.TempDir()
	fs, err := NewFileStore(dir, "")
	if err != nil {
		t.Fatalf("NewFileStore: %v", err)
	}
	return fs
}

func TestFileStore_WriteReadZone(t *testing.T) {
	fs := newTestStore(t)
	zf := zone.ZoneFile{
		TTL:    300,
		Serial: 1,
		Records: map[string]zone.RecordSet{
			"www.example.com.": {A: &zone.ARecord{IPv4: "1.2.3.4"}},
		},
	}

	if err := fs.WriteZone("example.com", zf); err != nil {
		t.Fatalf("WriteZone: %v", err)
	}

	got, err := fs.ReadZone("example.com")
	if err != nil {
		t.Fatalf("ReadZone: %v", err)
	}
	if got.TTL != 300 {
		t.Errorf("TTL = %d, want 300", got.TTL)
	}
	if got.Records["www.example.com."].A.IPv4 != "1.2.3.4" {
		t.Error("A record not preserved")
	}
}

func TestFileStore_ReadNonExistent(t *testing.T) {
	fs := newTestStore(t)
	_, err := fs.ReadZone("missing.example.com")
	if !errors.Is(err, os.ErrNotExist) {
		t.Errorf("expected os.ErrNotExist, got %v", err)
	}
}

func TestFileStore_DeleteZone(t *testing.T) {
	fs := newTestStore(t)
	zf := zone.ZoneFile{Serial: 1}
	if err := fs.WriteZone("del.example.com", zf); err != nil {
		t.Fatalf("WriteZone: %v", err)
	}

	if err := fs.DeleteZone("del.example.com"); err != nil {
		t.Fatalf("DeleteZone: %v", err)
	}

	if _, err := fs.ReadZone("del.example.com"); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("expected os.ErrNotExist after delete, got %v", err)
	}
}

func TestFileStore_DeleteNonExistent(t *testing.T) {
	fs := newTestStore(t)
	err := fs.DeleteZone("ghost.example.com")
	if !errors.Is(err, os.ErrNotExist) {
		t.Errorf("expected os.ErrNotExist, got %v", err)
	}
}

func TestFileStore_AtomicWrite(t *testing.T) {
	// After a successful write the .tmp file must not remain.
	fs := newTestStore(t)
	zf := zone.ZoneFile{Serial: 42}
	if err := fs.WriteZone("atomic.example.com", zf); err != nil {
		t.Fatalf("WriteZone: %v", err)
	}
	tmp := filepath.Join(fs.zonesDir, "atomic.example.com.yml.tmp")
	if _, err := os.Stat(tmp); !errors.Is(err, os.ErrNotExist) {
		t.Error("tmp file should not exist after successful write")
	}
}

func TestFileStore_WriteReadRawData(t *testing.T) {
	fs := newTestStore(t)
	data := []byte("+www.example.com:1.2.3.4:300\n")

	if err := fs.WriteRawData("my-key", data); err != nil {
		t.Fatalf("WriteRawData: %v", err)
	}

	got, err := fs.ReadRawData("my-key")
	if err != nil {
		t.Fatalf("ReadRawData: %v", err)
	}
	if string(got) != string(data) {
		t.Errorf("raw data mismatch: got %q, want %q", got, data)
	}
}

func TestFileStore_ReadRawDataNonExistent(t *testing.T) {
	fs := newTestStore(t)
	_, err := fs.ReadRawData("no-such-key")
	if !errors.Is(err, os.ErrNotExist) {
		t.Errorf("expected os.ErrNotExist, got %v", err)
	}
}

func TestFileStore_DeleteRawData(t *testing.T) {
	fs := newTestStore(t)
	if err := fs.WriteRawData("del-key", []byte("data")); err != nil {
		t.Fatalf("WriteRawData: %v", err)
	}
	if err := fs.DeleteRawData("del-key"); err != nil {
		t.Fatalf("DeleteRawData: %v", err)
	}
	if _, err := fs.ReadRawData("del-key"); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("expected os.ErrNotExist after delete, got %v", err)
	}
}

func TestFileStore_RawDataInRawSubdir(t *testing.T) {
	// Verify raw data is stored in the raw/ subdir, not the zones root.
	fs := newTestStore(t)
	if err := fs.WriteRawData("k", []byte("x")); err != nil {
		t.Fatalf("WriteRawData: %v", err)
	}
	expected := filepath.Join(fs.zonesDir, "raw", "k.data")
	if _, err := os.Stat(expected); err != nil {
		t.Errorf("expected raw file at %s, got error: %v", expected, err)
	}
	// Must not appear in zones root.
	wrong := filepath.Join(fs.zonesDir, "k.data")
	if _, err := os.Stat(wrong); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("raw file must not be in zones root")
	}
}
