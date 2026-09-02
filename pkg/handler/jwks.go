package handler

import "net/http"

// JWKS serves the JSON Web Key Set of ezauth's current asymmetric access-token
// signing key(s), letting independent resource servers verify ezauth-issued
// tokens without holding a shared secret. Returns an empty key set when
// signing with the default symmetric HS256 algorithm — there is nothing to
// publish, and the shared secret must never be exposed here.
// @Summary JSON Web Key Set
// @Tags jwt
// @Produce json
// @Success 200 {object} service.JWKSet
// @Router /.well-known/jwks.json [get]
func (h *Handler) JWKS(w http.ResponseWriter, r *http.Request) {
	WriteJSONResponse(w, http.StatusOK, h.svc.JWKS(), nil)
}
