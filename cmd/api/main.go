package main

import (
    "encoding/json"
    "log"
    "net/http"
)

type Response struct {
    Message string `json:"message"`
    Status  string `json:"status"`
}

func main() {
    // Define routes
    http.HandleFunc("/", handleHome)
    http.HandleFunc("/health", handleHealth)

    // Start server
    log.Println("Starting server on :8080")
    if err := http.ListenAndServe(":8080", nil); err != nil {
        log.Fatal(err)
    }
}

func handleHome( w http.ResponseWriter, r *http.Request) {
    response := Response{
        Message: "Welcome to Go Sandbox",
        Status: "success",
    }

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(response)
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
    response := Response{
        Message: "Server is running",
        Status: "up",
    }

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(response)
}