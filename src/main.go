package main

import (
	"fmt"
	"net/http"
)

func main() {
	http.HandleFunc("/hello", mainHandler)

	http.ListenAndServe(":8080", nil)
}

func mainHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Hello from HashiTalks 2024 v0.3")
}
