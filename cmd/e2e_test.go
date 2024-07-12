package main

import (
	"bytes"
	"io"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_Verify(t *testing.T) {
	tests := []struct {
		name         string
		policyPath   string
		resourcePath string
		outputPath   string
		fail         bool
	}{
		{
			name:         "cosign keyed pass",
			policyPath:   "./examples/cosign-keyed/policy.yaml",
			resourcePath: "./examples/cosign-keyed/payload.json",
			outputPath:   "./examples/cosign-keyed/out.txt",
		},
		{
			name:         "cosign keyed fail",
			policyPath:   "./examples/cosign-keyed/policy.yaml",
			resourcePath: "./examples/cosign-keyed/bad-payload.json",
			outputPath:   "./examples/cosign-keyed/bad-out.txt",
		},
		{
			name:         "cosign keyless pass",
			policyPath:   "./examples/cosign-keyless/policy.yaml",
			resourcePath: "./examples/cosign-keyless/payload.json",
			outputPath:   "./examples/cosign-keyless/out.txt",
		},
		{
			name:         "cosign keyless fail",
			policyPath:   "./examples/cosign-keyless/policy.yaml",
			resourcePath: "./examples/cosign-keyless/bad-payload.json",
			outputPath:   "./examples/cosign-keyless/bad-out.txt",
		},
		{
			name:         "notary attestation pass",
			policyPath:   "./examples/notary-attestation-verification/policy.yaml",
			resourcePath: "./examples/notary-attestation-verification/payload.json",
			outputPath:   "./examples/notary-attestation-verification/out.txt",
		},
		{
			name:         "notary attestation fail",
			policyPath:   "./examples/notary-attestation-verification/policy.yaml",
			resourcePath: "./examples/notary-attestation-verification/bad-payload.json",
			outputPath:   "./examples/notary-attestation-verification/bad-out.txt",
		},
		{
			name:         "notary image pass",
			policyPath:   "./examples/notary-image-verification/policy.yaml",
			resourcePath: "./examples/notary-image-verification/payload.json",
			outputPath:   "./examples/notary-image-verification/out.txt",
		},
		{
			name:         "notary image fail",
			policyPath:   "./examples/notary-image-verification/policy.yaml",
			resourcePath: "./examples/notary-image-verification/bad-payload.json",
			outputPath:   "./examples/notary-image-verification/bad-out.txt",
		},
		{
			name:         "wrong output test",
			policyPath:   "./examples/notary-image-verification/policy.yaml",
			resourcePath: "./examples/notary-image-verification/payload.json",
			outputPath:   "./examples/notary-image-verification/bad-out.txt",
			fail:         true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out := bytes.NewBufferString("")
			verify(out, tt.resourcePath, tt.policyPath)
			actual, err := io.ReadAll(out)
			assert.NoError(t, err)
			if tt.outputPath != "" {
				expected, err := os.ReadFile(tt.outputPath)
				assert.NoError(t, err)
				if !tt.fail {
					assert.Equal(t, string(expected), string(actual))
				} else {
					assert.NotEqual(t, string(expected), string(actual))
				}
			}
		})

	}
}
