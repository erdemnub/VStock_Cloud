package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/erdemnub/VStock_Cloud/internal/auth"
)

const (
	MaxUploadSize int64 = 10 << 20 // 10 MB
	Port                = ":8080"
	QuarantineDir       = "./data/quarantine"
)

var allowedExtensions = map[string]bool{
	".pdf":  true,
	".png":  true,
	".jpg":  true,
	".jpeg": true,
	".txt":  true,
	".csv":  true,
	".xls":  true,
	".xlsx": true,
}

type UploadResponse struct {
	Version   string `json:"version"`
	Status    string `json:"status"`
	Filename  string `json:"filename"`
	SHA256    string `json:"sha256_hash"`
	Role      string `json:"authorized_role"`
	Timestamp string `json:"timestamp"`
}

func main() {
	if err := os.MkdirAll(QuarantineDir, 0750); err != nil {
		log.Fatal(err)
	}

	rbac := auth.NewRBAC("admin", "secops")

	mux := http.NewServeMux()

	mux.HandleFunc("/healthz", healthHandler)

	mux.Handle(
		"/api/v1/upload",
		rbac.Middleware(http.HandlerFunc(uploadHandler)),
	)

	server := &http.Server{
		Addr:              Port,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	log.Printf("VStock Cloud backend listening on %s", Port)
	log.Fatal(server.ListenAndServe())
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(
			w,
			http.StatusMethodNotAllowed,
			"method not allowed",
		)
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{
		"status":  "ok",
		"service": "vstock-cloud",
		"version": "v0.1.0",
	})
}

func uploadHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(
			w,
			http.StatusMethodNotAllowed,
			"method not allowed",
		)
		return
	}

	// İstek gövdesini 10 MB ile sınırlandırır.
	r.Body = http.MaxBytesReader(
		w,
		r.Body,
		MaxUploadSize,
	)

	if err := r.ParseMultipartForm(MaxUploadSize); err != nil {
		writeError(
			w,
			http.StatusRequestEntityTooLarge,
			"file exceeds 10 MB limit",
		)
		return
	}

	file, header, err := r.FormFile("file")
	if err != nil {
		writeError(
			w,
			http.StatusBadRequest,
			"multipart field 'file' is required",
		)
		return
	}
	defer file.Close()

	// Kullanıcı tarafından gelen path bilgisini temizler.
	safeFilename := filepath.Base(header.Filename)
	extension := strings.ToLower(filepath.Ext(safeFilename))

	if !allowedExtensions[extension] {
		writeError(
			w,
			http.StatusUnsupportedMediaType,
			"file extension is not allowed",
		)
		return
	}

	tempFile, err := os.CreateTemp(
		QuarantineDir,
		"upload-*",
	)
	if err != nil {
		writeError(
			w,
			http.StatusInternalServerError,
			"temporary file could not be created",
		)
		return
	}

	tempPath := tempFile.Name()
	defer os.Remove(tempPath)
	defer tempFile.Close()

	hasher := sha256.New()
	writer := io.MultiWriter(tempFile, hasher)

	// Limit aşımını tespit etmek için MaxUploadSize + 1 okunur.
	reader := io.LimitReader(
		file,
		MaxUploadSize+1,
	)

	size, err := io.Copy(writer, reader)
	if err != nil {
		writeError(
			w,
			http.StatusBadRequest,
			"file could not be read",
		)
		return
	}

	if size > MaxUploadSize {
		writeError(
			w,
			http.StatusRequestEntityTooLarge,
			"file exceeds 10 MB limit",
		)
		return
	}

	hash := hex.EncodeToString(hasher.Sum(nil))

	// Aynı dosya adı yerine hash tabanlı güvenli isim kullanılır.
	finalName := fmt.Sprintf(
		"%s%s",
		hash,
		extension,
	)

	finalPath := filepath.Join(
		QuarantineDir,
		finalName,
	)

	if err := tempFile.Close(); err != nil {
		writeError(
			w,
			http.StatusInternalServerError,
			"temporary file could not be closed",
		)
		return
	}

	if err := os.Rename(tempPath, finalPath); err != nil {
		writeError(
			w,
			http.StatusInternalServerError,
			"file could not be moved to quarantine",
		)
		return
	}

	response := UploadResponse{
		Version:   "v0.1.0",
		Status:    "quarantine_pending_scan",
		Filename:  safeFilename,
		SHA256:    hash,
		Role:      r.Header.Get("X-User-Role"),
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	}

	log.Printf(
		"upload accepted filename=%s sha256=%s size=%d",
		safeFilename,
		hash,
		size,
	)

	writeJSON(w, http.StatusAccepted, response)
}

func writeJSON(
	w http.ResponseWriter,
	status int,
	value any,
) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)

	_ = json.NewEncoder(w).Encode(value)
}

func writeError(
	w http.ResponseWriter,
	status int,
	message string,
) {
	writeJSON(w, status, map[string]string{
		"error": message,
	})
}
