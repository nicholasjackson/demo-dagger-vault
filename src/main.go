package main

import (
	"fmt"
	"net/http"
)

func main() {
	http.HandleFunc("/hello", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Hello from HashiTalks 2024 v0.2")
	})

	http.ListenAndServe(":8080", nil)
}
