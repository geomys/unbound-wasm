package unbound

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/tetratelabs/wazero"
)

func TestEmbeddedModuleHash(t *testing.T) {
	h := sha256.Sum256(embeddedModule)
	if got := hex.EncodeToString(h[:]); got != moduleSHA256 {
		t.Fatalf("embedded hash %s, constant %s", got, moduleSHA256)
	}
}

func TestEmbeddedModuleABIShape(t *testing.T) {
	ctx := context.Background()
	wr := wazero.NewRuntime(ctx)
	defer wr.Close(ctx)
	compiled, err := wr.CompileModule(ctx, embeddedModule)
	if err != nil {
		t.Fatal(err)
	}
	for _, def := range compiled.ImportedFunctions() {
		module, name, _ := def.Import()
		if module != "unbound_wasm" && module != "wasi_snapshot_preview1" {
			t.Fatalf("unexpected import %s.%s", module, name)
		}
	}
	for _, name := range []string{"unbound_wasm_abi_version", "alloc", "dealloc", "init", "resolve_start", "io_ready", "timer_fired", "result_get", "resolve_cancel"} {
		if _, ok := compiled.ExportedFunctions()[name]; !ok {
			t.Errorf("missing export %s", name)
		}
	}
}

func TestRootHints(t *testing.T) {
	ctx := context.Background()
	for _, hints := range [][]string{
		{"not an address"},
		{"192.0.2.0/24"},
		{"127.0.0.1"},
		{"10.0.0.1"},
		{"198.41.0.4", "fe80::1"},
	} {
		if _, err := NewRuntime(ctx, Config{RootHints: hints}); err == nil {
			t.Errorf("NewRuntime(RootHints: %q) succeeded, want error", hints)
		}
	}
	rt, err := NewRuntime(ctx, Config{RootHints: []string{"198.41.0.4", "2001:503:ba3e::2:30"}})
	if err != nil {
		t.Fatal(err)
	}
	defer rt.Close(ctx)
	// The guest validates the hints syntax on the first resolution, when
	// the libunbound context is created; instantiation only stores them.
	inst, err := rt.NewInstance(ctx)
	if err != nil {
		t.Fatal(err)
	}
	inst.Close(ctx)
}

func TestRuntimeCloseClosesInstances(t *testing.T) {
	ctx := context.Background()
	rt, err := NewRuntime(ctx, Config{})
	if err != nil {
		t.Fatal(err)
	}
	inst, err := rt.NewInstance(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := rt.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := inst.Resolve(ctx, "example.com.", TypeA); err == nil {
		t.Fatal("Resolve succeeded after runtime close")
	}
	if _, err := rt.NewInstance(ctx); err == nil {
		t.Fatal("NewInstance succeeded after runtime close")
	}
}

func TestEmptyNameRejected(t *testing.T) {
	ctx := context.Background()
	rt, err := NewRuntime(ctx, Config{})
	if err != nil {
		t.Fatal(err)
	}
	defer rt.Close(ctx)
	inst, err := rt.NewInstance(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer inst.Close(ctx)
	_, err = inst.Resolve(ctx, "", TypeA)
	if err == nil || errors.Is(err, ErrClosed) {
		t.Fatalf("unexpected error: %v", err)
	}
}
