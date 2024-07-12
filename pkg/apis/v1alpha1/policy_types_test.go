package v1alpha1

import (
	"encoding/json"
	"testing"
)

func Test_VerificationPolicyValidation(t *testing.T) {
	tests := []struct {
		name   string
		policy string
		err    error
	}{
		{
			name:   "cosign key verification",
			policy: `{"imageReferences":"*","cosign":[{"key":{"publicKey":""}}]}`,
		},
		{
			name:   "cosign keyless verifiaction",
			policy: `{"imageReferences":"*","cosign":[{"keyless":{"issuer":"","subject":"","root":""}}]}`,
		},
		{
			name:   "cosign certificate verification",
			policy: `{"imageReferences":"*","cosign":[{"certificate":{"cert":"","certChain":""}}]}`,
		},
		{
			name:   "cosign both key and keyless",
			policy: `{"imageReferences":"*","cosign":[{"key":{"publicKey":""},"keyless":{"issuer":"","subject":"","root":""}}]}`,
			err:    errMultipleAttestor,
		},
		{
			name:   "cosign both key and cert",
			policy: `{"imageReferences":"*","cosign":[{"key":{"publicKey":""},"certificate":{"cert":"","certChain":""}}]}`,
			err:    errMultipleAttestor,
		},
		{
			name:   "cosign both keyless and certificate",
			policy: `{"imageReferences":"*","cosign":[{"keyless":{"issuer":"","subject":"","root":""},"certificate":{"cert":"","certChain":""}}]}`,
			err:    errMultipleAttestor,
		},
		{
			name:   "cosign key, keyless and certificate",
			policy: `{"imageReferences":"*","cosign":[{"key":{"publicKey":""},"keyless":{"issuer":"","subject":"","root":""},"certificate":{"cert":"","certChain":""}}]}`,
			err:    errMultipleAttestor,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var policy VerificationRule
			if err := json.Unmarshal([]byte(tt.policy), &policy); err != nil {
				t.Fatal(err)
			}

			if err := policy.Validate(); err != tt.err {
				t.Errorf("test: %s failed, want=%v, got=%v", tt.name, tt.err, err)
			}
		})
	}
}
