// Deliberately vulnerable Go API for the DevSecOps PoC.
//
// WARNING: this app contains intentional security flaws so that scanners have
// something to find. Never expose it to a network you don't control.
// Each planted flaw is tagged with `VULN:`.
package main

import (
	"crypto/md5" // VULN: weak hash algorithm
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"time"

	jwt "github.com/dgrijalva/jwt-go" // VULN: unmaintained, CVE-2020-26160
	"golang.org/x/text/language"
	"gopkg.in/yaml.v2"
)

// VULN: hardcoded signing secret
var jwtSecret = []byte("super-secret-poc-key")

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func health(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func ping(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("host")
	if host == "" {
		host = "127.0.0.1"
	}
	// VULN: OS command injection (user input in a shell string). Try ?host=127.0.0.1;id
	out, err := exec.Command("sh", "-c", "ping -c 1 "+host).CombinedOutput()
	writeJSON(w, http.StatusOK, map[string]any{"output": string(out), "error": fmt.Sprint(err)})
}

func lang(w http.ResponseWriter, r *http.Request) {
	// Uses golang.org/x/text v0.3.7: language.Parse is vulnerable to DoS (CVE-2022-32149)
	tags, _, err := language.ParseAcceptLanguage(r.Header.Get("Accept-Language"))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"languages": fmt.Sprint(tags)})
}

func config(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	var data map[string]any
	// Uses gopkg.in/yaml.v2 v2.2.7: crafted YAML can exhaust CPU/memory (CVE-2019-11254)
	if err := yaml.Unmarshal(body, &data); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"parsed": fmt.Sprint(data)})
}

func fetch(w http.ResponseWriter, r *http.Request) {
	url := r.URL.Query().Get("url")
	// VULN: SSRF (server fetches any user-supplied URL)
	resp, err := http.Get(url) //nolint:gosec,noctx
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}
	defer resp.Body.Close()
	writeJSON(w, http.StatusOK, map[string]int{"status": resp.StatusCode})
}

func token(w http.ResponseWriter, r *http.Request) {
	claims := jwt.MapClaims{"user": r.URL.Query().Get("user"), "iat": time.Now().Unix()}
	signed, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(jwtSecret)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"token": signed})
}

func hash(w http.ResponseWriter, r *http.Request) {
	sum := md5.Sum([]byte(r.URL.Query().Get("value")))
	writeJSON(w, http.StatusOK, map[string]string{"md5": hex.EncodeToString(sum[:])})
}

func newMux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", health)
	mux.HandleFunc("GET /ping", ping)
	mux.HandleFunc("GET /lang", lang)
	mux.HandleFunc("POST /config", config)
	mux.HandleFunc("GET /fetch", fetch)
	mux.HandleFunc("GET /token", token)
	mux.HandleFunc("GET /hash", hash)
	return mux
}

func main() {
	// `poc-go healthcheck` lets the distroless image (no shell, no curl) run a HEALTHCHECK
	if len(os.Args) > 1 && os.Args[1] == "healthcheck" {
		resp, err := http.Get("http://127.0.0.1:8080/health")
		if err != nil || resp.StatusCode != http.StatusOK {
			os.Exit(1)
		}
		return
	}
	log.Println("listening on :8080")
	// VULN: no server timeouts (slowloris)
	log.Fatal(http.ListenAndServe(":8080", newMux())) //nolint:gosec
}
