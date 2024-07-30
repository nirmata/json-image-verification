package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/nirmata/json-image-verification/pkg/imageverifier"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("usage: ./verifier <POLICY> <RESOURCE>")
	}
	policyPath := flag.String("policy", "", "path to policy")
	resourcePath := flag.String("resource", "", "path to resource")
	flag.Parse()

	verify(os.Stdout, *resourcePath, *policyPath)
}

func verify(out io.Writer, resourcePath, policyPath string) {
	b, err := os.ReadFile(resourcePath)
	if err != nil {
		panic(err)
	}

	var resource interface{}
	if err := json.Unmarshal(b, &resource); err != nil {
		panic(err)
	}

	pol, err := Load(policyPath)
	if err != nil {
		panic(err)
	}

	verifier := imageverifier.NewEngineFromDClient(nil)
	request := imageverifier.Request{
		Policies: pol,
		Resource: resource,
	}
	response := verifier.Apply(request)

	fmt.Fprintln(out, "Verification Result:")
	for _, p := range response.PolicyResponses {
		fmt.Fprintf(out, "Results for policy: %s\n", p.Policy.Name)
		for _, r := range p.RuleResponses {
			fmt.Fprintf(out, "Results for rule: %s\n", r.Rule.Name)
			resp := r.VerificationResult
			fmt.Fprintf(out, "Verifying image: %s, result: %s\n", resp.Image, resp.VerificationOutcome)
			switch resp.VerificationOutcome {
			case imageverifier.ERROR:
				fmt.Fprintf(out, "Error encountered: %v\n", resp.Error)
			case imageverifier.FAIL:
				fmt.Fprintf(out, "Failures:\n")
				for _, vresp := range resp.VerificationResponses {
					for _, err := range vresp.Failures {
						fmt.Fprintln(out, err)
					}
				}
			}
		}
	}
}
