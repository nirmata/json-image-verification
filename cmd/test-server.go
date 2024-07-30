package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/nirmata/kyverno-notation-verifier/pkg/types"
)

func server() {
	mux := http.NewServeMux()
	mux.HandleFunc("/", echo)
	srv := &http.Server{
		Addr:    "127.0.0.1:3000",
		Handler: mux,
	}

	fmt.Println("server started at", srv.Addr)
	err := srv.ListenAndServe()
	if err != nil {
		panic(err)
	}
}

func echo(w http.ResponseWriter, r *http.Request) {
	raw, _ := io.ReadAll(r.Body)

	var requestData types.RequestData
	err := json.Unmarshal(raw, &requestData)
	if err != nil {
		fmt.Printf("failed to decode %s: %v\n", string(raw), err)
		http.Error(w, err.Error(), http.StatusNotAcceptable)
		return
	}

	if len(requestData.ImageReferences) == 0 {
		http.Error(w, "image references not found", http.StatusNotAcceptable)
		return
	}

	if len(requestData.Images.Containers)+len(requestData.Images.Containers)+len(requestData.Images.Containers) == 0 {
		http.Error(w, "no images were provided", http.StatusNotAcceptable)
		return
	}

	data, err := json.MarshalIndent(requestData, "", " ")
	fmt.Printf("Request recieved with data=%+v\n", string(data))

	var resp types.ResponseData
	resp.Verified = true
	data, err = json.MarshalIndent(resp, "  ", "  ")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	fmt.Printf("Sending response %s\n", string(data))
	w.WriteHeader(http.StatusOK)
	w.Write(data)
}
