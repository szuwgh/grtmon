package main

import (
    "fmt"
    "net/http"
)

func IndexHandler(w http.ResponseWriter, r *http.Request) {
    fmt.Fprintln(w, "hello world")
}

func main() {
    port := "8001"
    http.HandleFunc("/", IndexHandler)
    fmt.Println("listen...", port)  
    http.ListenAndServe(":"+port, nil)
}
