package main 
import (
	"log"
	"net/http"
	"encoding/json"
)

type HealthResponse struct {
	Status string `json:"status"`
}

func 