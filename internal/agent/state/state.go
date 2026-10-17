// Package state persists the agent's identity between runs.
package state

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/sneakybugmaster/transporter/internal/wgkey"
)

const fileName = "state.json"

// State is everything the agent must remember across restarts.
type State struct {
	PrivateKey     wgkey.Key `json:"privateKey"`
	CoordinatorURL string    `json:"coordinatorURL,omitempty"`
	NodeID         string    `json:"nodeID,omitempty"`
	NodeToken      string    `json:"nodeToken,omitempty"`
	Name           string    `json:"name,omitempty"`
}

// Registered reports whether the node holds a token for coordinatorURL.
func (s *State) Registered(coordinatorURL string) bool {
	return s.NodeToken != "" && s.CoordinatorURL == coordinatorURL
}

// Load reads the state from dir, generating a fresh private key if no state
// file exists yet.
func Load(dir string) (*State, error) {
	b, err := os.ReadFile(filepath.Join(dir, fileName)) //nolint:gosec // operator-supplied state dir
	if errors.Is(err, fs.ErrNotExist) {
		key, err := wgkey.NewPrivate()
		if err != nil {
			return nil, err
		}
		return &State{PrivateKey: key}, nil
	}
	if err != nil {
		return nil, err
	}
	var s State
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, fmt.Errorf("parse %s: %w", fileName, err)
	}
	if s.PrivateKey.IsZero() {
		return nil, fmt.Errorf("%s: missing private key", fileName)
	}
	return &s, nil
}

// Save atomically writes the state to dir with owner-only permissions.
func (s *State) Save(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(s, "", "  ") //nolint:gosec // persisting the key is the point; file is 0600
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, fileName+".*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name()) // no-op after a successful rename
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(append(b, '\n')); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), filepath.Join(dir, fileName))
}
