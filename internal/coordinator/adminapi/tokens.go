package adminapi

import (
	"net/http"
	"strings"
	"time"

	"github.com/sneakybugmaster/transporter/internal/coordinator/store"
)

// sessionOnly refuses requests made with an API token: a leaked token must
// not be able to mint more tokens or take over the account.
func (s *Server) sessionOnly(w http.ResponseWriter, r *http.Request) bool {
	if viaToken(r) {
		writeError(w, http.StatusForbidden, "not allowed with an API token; sign in to the console")
		return false
	}
	return true
}

func (s *Server) ListAPITokens(w http.ResponseWriter, r *http.Request) {
	if !s.sessionOnly(w, r) {
		return
	}
	tokens, err := s.store.ListAPITokens(r.Context())
	if err != nil {
		s.internal(w, err)
		return
	}
	out := make([]APIToken, 0, len(tokens))
	for _, t := range tokens {
		out = append(out, tokenJSON(t))
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) CreateAPIToken(w http.ResponseWriter, r *http.Request) {
	if !s.sessionOnly(w, r) {
		return
	}
	var req APITokenCreate
	if !decode(w, r, &req) {
		return
	}
	ttl := time.Duration(req.TtlSeconds) * time.Second
	if req.TtlSeconds < 0 || ttl > 2*maxKeyTTL {
		writeError(w, http.StatusBadRequest, "ttlSeconds must be between 0 (never expires) and two years")
		return
	}
	desc := ""
	if req.Description != nil {
		desc = strings.TrimSpace(*req.Description)
	}
	if len(desc) > 200 {
		writeError(w, http.StatusBadRequest, "description is too long")
		return
	}
	t, secret, err := s.store.CreateAPIToken(r.Context(), admin(r).ID, desc, ttl)
	if err != nil {
		s.internal(w, err)
		return
	}
	t.Admin = admin(r).Username
	s.audit(r, "token.create", t.ID, desc)
	writeJSON(w, http.StatusCreated, APITokenCreated{Token: tokenJSON(t), Secret: secret})
}

func (s *Server) DeleteAPIToken(w http.ResponseWriter, r *http.Request, id string) {
	if !s.sessionOnly(w, r) {
		return
	}
	if s.storeErr(w, s.store.DeleteAPIToken(r.Context(), id)) {
		return
	}
	s.audit(r, "token.revoke", id, "")
	w.WriteHeader(http.StatusNoContent)
}

func tokenJSON(t store.APIToken) APIToken {
	return APIToken{
		Id: t.ID, Description: t.Description, Admin: t.Admin,
		CreatedAt: t.CreatedAt, ExpiresAt: t.ExpiresAt, LastUsed: t.LastUsed,
	}
}
