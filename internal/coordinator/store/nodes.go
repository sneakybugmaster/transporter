package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/sneakybugmaster/transporter/internal/agent/magicdns"
	"github.com/sneakybugmaster/transporter/internal/coordinator/ipam"
)

// NodeTokenPrefix starts every node token.
const NodeTokenPrefix = "trn_"

// Node is a machine enrolled in the mesh.
type Node struct {
	ID          string
	Name        string
	Hostname    string
	OS          string
	WGPublicKey [32]byte
	IPv4        netip.Addr
	Endpoints   []string
	Tags        []string
	// AdvertisedRoutes are the subnet routes the node offers to forward
	// (0.0.0.0/0 for an exit node); ApprovedRoutes are those an admin or the
	// policy allowed. Routes() is what is in effect.
	AdvertisedRoutes []netip.Prefix
	ApprovedRoutes   []netip.Prefix
	CreatedAt        time.Time
	LastSeen         time.Time
}

// Routes returns the routes in effect: advertised and approved.
func (n Node) Routes() []netip.Prefix {
	var out []netip.Prefix
	for _, r := range n.AdvertisedRoutes {
		if slices.Contains(n.ApprovedRoutes, r) {
			out = append(out, r)
		}
	}
	return out
}

// RegisterRequest holds what a node presents when enrolling.
type RegisterRequest struct {
	AuthKey     string
	WGPublicKey [32]byte
	Hostname    string
	OS          string
	// Prefix is the overlay network new addresses are allocated from.
	Prefix netip.Prefix
}

// RegisterNode validates the auth key and enrolls the node, or re-enrolls it
// if its WireGuard key is already known. It returns the node and a new token;
// any previous token for the node stops working.
func (s *Store) RegisterNode(ctx context.Context, req RegisterRequest) (Node, string, error) {
	var (
		node  Node
		token = newSecret(NodeTokenPrefix)
		now   = s.now().UTC().Truncate(time.Second)
	)
	err := s.inTx(ctx, func(tx *sql.Tx) error {
		key, err := s.authKeyByHash(ctx, tx, hashSecret(req.AuthKey))
		if errors.Is(err, ErrNotFound) || (err == nil && !key.Valid(now)) {
			return ErrInvalidAuthKey
		}
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE auth_keys SET used_count = used_count + 1 WHERE id = ?`, key.ID); err != nil {
			return err
		}

		existing, err := scanNode(tx.QueryRowContext(ctx, `SELECT `+nodeColumns+` FROM nodes WHERE wg_public_key = ?`, req.WGPublicKey[:]))
		switch {
		case err == nil:
			node = existing
			node.Hostname, node.OS, node.LastSeen = req.Hostname, req.OS, now
			if len(key.Tags) > 0 {
				node.Tags = key.Tags // re-enrolling with a tagged key retags the node
			}
			_, err = tx.ExecContext(ctx,
				`UPDATE nodes SET token_hash = ?, hostname = ?, os = ?, last_seen = ?, auth_key_id = ?, tags = ? WHERE id = ?`,
				hashSecret(token), node.Hostname, node.OS, now.Unix(), key.ID, jsonList(node.Tags), node.ID)
			return err
		case !errors.Is(err, sql.ErrNoRows):
			return err
		}

		ip, err := allocateIP(ctx, tx, req.Prefix)
		if err != nil {
			return err
		}
		name, err := uniqueName(ctx, tx, SanitizeName(req.Hostname))
		if err != nil {
			return err
		}
		node = Node{
			ID:          newID(),
			Name:        name,
			Hostname:    req.Hostname,
			OS:          req.OS,
			WGPublicKey: req.WGPublicKey,
			IPv4:        ip,
			Tags:        key.Tags,
			CreatedAt:   now,
			LastSeen:    now,
		}
		_, err = tx.ExecContext(ctx,
			`INSERT INTO nodes (id, name, hostname, os, wg_public_key, ipv4, token_hash, auth_key_id, created_at, last_seen, tags)
			 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			node.ID, node.Name, node.Hostname, node.OS, node.WGPublicKey[:], node.IPv4.String(),
			hashSecret(token), key.ID, now.Unix(), now.Unix(), jsonList(node.Tags))
		return err
	})
	if err != nil {
		return Node{}, "", err
	}
	return node, token, nil
}

// NodeByToken returns the node that owns token.
func (s *Store) NodeByToken(ctx context.Context, token string) (Node, error) {
	return s.nodeWhere(ctx, `token_hash = ?`, hashSecret(token))
}

// NodeByID returns a node by ID.
func (s *Store) NodeByID(ctx context.Context, id string) (Node, error) {
	return s.nodeWhere(ctx, `id = ?`, id)
}

// NodeByName returns a node by name.
func (s *Store) NodeByName(ctx context.Context, name string) (Node, error) {
	return s.nodeWhere(ctx, `name = ?`, name)
}

func (s *Store) nodeWhere(ctx context.Context, where string, arg any) (Node, error) {
	n, err := scanNode(s.db.QueryRowContext(ctx, `SELECT `+nodeColumns+` FROM nodes WHERE `+where, arg))
	if errors.Is(err, sql.ErrNoRows) {
		return Node{}, ErrNotFound
	}
	return n, err
}

// ListNodes returns all nodes ordered by address.
func (s *Store) ListNodes(ctx context.Context) ([]Node, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+nodeColumns+` FROM nodes`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var nodes []Node
	for rows.Next() {
		n, err := scanNode(rows)
		if err != nil {
			return nil, err
		}
		nodes = append(nodes, n)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	slices.SortFunc(nodes, func(a, b Node) int { return a.IPv4.Compare(b.IPv4) })
	return nodes, nil
}

// UpdateNodeEndpoints records the endpoints a node reported and marks it seen.
func (s *Store) UpdateNodeEndpoints(ctx context.Context, id string, endpoints []string) error {
	if endpoints == nil {
		endpoints = []string{}
	}
	b, err := json.Marshal(endpoints)
	if err != nil {
		return err
	}
	return s.updateNode(ctx, `UPDATE nodes SET endpoints = ?, last_seen = ? WHERE id = ?`, string(b), s.now().Unix(), id)
}

// SetNodeTags replaces a node's tags.
func (s *Store) SetNodeTags(ctx context.Context, id string, tags []string) (Node, error) {
	if err := s.updateNode(ctx, `UPDATE nodes SET tags = ? WHERE id = ?`, jsonList(tags), id); err != nil {
		return Node{}, err
	}
	return s.NodeByID(ctx, id)
}

// SetAdvertisedRoutes records the routes a node offers.
func (s *Store) SetAdvertisedRoutes(ctx context.Context, id string, routes []netip.Prefix) error {
	return s.updateNode(ctx, `UPDATE nodes SET advertised_routes = ? WHERE id = ?`, jsonList(routes), id)
}

// SetApprovedRoutes replaces the routes a node may use.
func (s *Store) SetApprovedRoutes(ctx context.Context, id string, routes []netip.Prefix) (Node, error) {
	if err := s.updateNode(ctx, `UPDATE nodes SET approved_routes = ? WHERE id = ?`, jsonList(routes), id); err != nil {
		return Node{}, err
	}
	return s.NodeByID(ctx, id)
}

// TouchNode updates a node's last-seen time.
func (s *Store) TouchNode(ctx context.Context, id string) error {
	return s.updateNode(ctx, `UPDATE nodes SET last_seen = ? WHERE id = ?`, s.now().Unix(), id)
}

// updateNode runs an UPDATE statement and reports ErrNotFound if no row matched.
func (s *Store) updateNode(ctx context.Context, query string, args ...any) error {
	res, err := s.db.ExecContext(ctx, query, args...)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// RenameNode changes a node's name, sanitising it to a DNS label.
func (s *Store) RenameNode(ctx context.Context, id, name string) (Node, error) {
	clean := SanitizeName(name)
	_, err := s.db.ExecContext(ctx, `UPDATE nodes SET name = ? WHERE id = ?`, clean, id)
	if err != nil && strings.Contains(err.Error(), "UNIQUE") {
		return Node{}, ErrConflict
	}
	if err != nil {
		return Node{}, err
	}
	return s.NodeByID(ctx, id)
}

// DeleteNode removes a node; its address becomes free for reuse.
func (s *Store) DeleteNode(ctx context.Context, id string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM nodes WHERE id = ?`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

const nodeColumns = `id, name, hostname, os, wg_public_key, ipv4, endpoints, created_at, last_seen, tags, advertised_routes, approved_routes`

func scanNode(row scanner) (Node, error) {
	var (
		n                   Node
		key                 []byte
		ip, endpoints       string
		createdAt, lastSeen int64
		tags, adv, appr     string
	)
	if err := row.Scan(&n.ID, &n.Name, &n.Hostname, &n.OS, &key, &ip, &endpoints, &createdAt, &lastSeen, &tags, &adv, &appr); err != nil {
		return Node{}, err
	}
	if len(key) != len(n.WGPublicKey) {
		return Node{}, fmt.Errorf("node %s: bad public key length %d", n.ID, len(key))
	}
	copy(n.WGPublicKey[:], key)
	var err error
	if n.IPv4, err = netip.ParseAddr(ip); err != nil {
		return Node{}, fmt.Errorf("node %s: %w", n.ID, err)
	}
	if err := json.Unmarshal([]byte(endpoints), &n.Endpoints); err != nil {
		return Node{}, fmt.Errorf("node %s endpoints: %w", n.ID, err)
	}
	if err := json.Unmarshal([]byte(tags), &n.Tags); err != nil {
		return Node{}, fmt.Errorf("node %s tags: %w", n.ID, err)
	}
	if err := json.Unmarshal([]byte(adv), &n.AdvertisedRoutes); err != nil {
		return Node{}, fmt.Errorf("node %s advertised routes: %w", n.ID, err)
	}
	if err := json.Unmarshal([]byte(appr), &n.ApprovedRoutes); err != nil {
		return Node{}, fmt.Errorf("node %s approved routes: %w", n.ID, err)
	}
	n.CreatedAt = time.Unix(createdAt, 0).UTC()
	n.LastSeen = time.Unix(lastSeen, 0).UTC()
	return n, nil
}

// jsonList encodes a list column; nil becomes [].
func jsonList[T any](v []T) string {
	if v == nil {
		return "[]"
	}
	b, _ := json.Marshal(v) // strings and netip.Prefix always marshal
	return string(b)
}

func allocateIP(ctx context.Context, tx *sql.Tx, prefix netip.Prefix) (netip.Addr, error) {
	rows, err := tx.QueryContext(ctx, `SELECT ipv4 FROM nodes`)
	if err != nil {
		return netip.Addr{}, err
	}
	defer rows.Close()
	used := map[netip.Addr]bool{}
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			return netip.Addr{}, err
		}
		if a, err := netip.ParseAddr(s); err == nil {
			used[a] = true
		}
	}
	if err := rows.Err(); err != nil {
		return netip.Addr{}, err
	}
	used[magicdns.Addr] = true // answered by every agent itself
	return ipam.Allocate(prefix, func(a netip.Addr) bool { return used[a] })
}

func uniqueName(ctx context.Context, tx *sql.Tx, base string) (string, error) {
	name := base
	for i := 2; ; i++ {
		var exists bool
		if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM nodes WHERE name = ?)`, name).Scan(&exists); err != nil {
			return "", err
		}
		if !exists {
			return name, nil
		}
		suffix := fmt.Sprintf("-%d", i)
		name = strings.TrimRight(base[:min(len(base), 63-len(suffix))], "-") + suffix
	}
}

// SanitizeName turns a hostname into a DNS label: lowercase letters, digits
// and hyphens, at most 63 characters.
func SanitizeName(hostname string) string {
	if i := strings.IndexByte(hostname, '.'); i > 0 {
		hostname = hostname[:i]
	}
	var b strings.Builder
	for _, r := range strings.ToLower(hostname) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		case b.Len() > 0 && !strings.HasSuffix(b.String(), "-"):
			b.WriteByte('-')
		}
	}
	name := strings.Trim(b.String(), "-")
	if len(name) > 63 {
		name = strings.TrimRight(name[:63], "-")
	}
	if name == "" {
		name = "node"
	}
	return name
}
