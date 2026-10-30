package auth

import (
	"log"
	"net/http"
	"strings"
)

type RBAC struct {
	AllowedRoles map[string]struct{}
}

func NewRBAC(roles ...string) RBAC {
	allowed := make(map[string]struct{})

	for _, role := range roles {
		role = strings.ToLower(strings.TrimSpace(role))
		allowed[role] = struct{}{}
	}

	return RBAC{
		AllowedRoles: allowed,
	}
}

func (a RBAC) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		role := strings.ToLower(
			strings.TrimSpace(r.Header.Get("X-User-Role")),
		)

		if _, allowed := a.AllowedRoles[role]; !allowed {
			log.Printf(
				"RBAC denied: role=%q remote=%q",
				role,
				r.RemoteAddr,
			)

			writeJSONError(
				w,
				http.StatusForbidden,
				"forbidden: insufficient role",
			)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func writeJSONError(
	w http.ResponseWriter,
	status int,
	message string,
) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)

	_, _ = w.Write([]byte(
		`{"error":"` + message + `"}`,
	))
}
