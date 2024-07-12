package v1alpha1

import (
	"fmt"

	"github.com/kyverno/kyverno-json/pkg/apis/policy/v1alpha1"
	kyvernov1 "github.com/kyverno/kyverno/api/kyverno/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var errMultipleAttestor = fmt.Errorf("multiple attestor cannot be added in the same entry")

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:object:root=true
// +kubebuilder:resource:scope=Cluster
// +kubebuilder:storageversion

// ImageVerificationPolicy defines rules to verify images used in matching resources
type ImageVerificationPolicy struct {
	metav1.TypeMeta `json:",inline" yaml:",inline"`

	// Standard object's metadata.
	// +optional
	metav1.ObjectMeta `json:"metadata,omitempty" yaml:"metadata,omitempty"`

	// ImageVerificationPolicy spec.
	Spec ImageVerificationPolicySpec `json:"spec" yaml:"spec"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// ImageVerificationPolicyList is a list of ValidatingPolicy instances.
type ImageVerificationPolicyList struct {
	metav1.TypeMeta `json:",inline" yaml:",inline"`
	metav1.ListMeta `json:"metadata" yaml:"metadata"`
	Items           []ImageVerificationPolicy `json:"items" yaml:"items"`
}

type ImageVerificationPolicySpec struct {
	Rules []ImageVerificationRule `json:"rules"`
}

type ImageVerificationRule struct {
	Name string `json:"name"`
	// +optional
	Match          v1alpha1.Match        `json:"match"`
	ImageExtractor ImageExtractorConfigs `json:"imageExtractors"`
	// +optional
	RequiredCount int               `json:"count"`
	Rules         VerificationRules `json:"verify"`
}

type ImageExtractorConfigs []ImageExtractorConfig

type ImageExtractorConfig struct {
	// Path is the path to the object containing the image field in a custom resource.
	// It should be slash-separated. Each slash-separated key must be a valid YAML key or a wildcard '*'.
	// Wildcard keys are expanded in case of arrays or objects.
	Path string `json:"path" yaml:"path"`
	// Value is an optional name of the field within 'path' that points to the image URI.
	// This is useful when a custom 'key' is also defined.
	// +optional
	Value string `json:"value,omitempty" yaml:"value,omitempty"`
	// Name is the entry the image will be available under 'images.<name>' in the context.
	// If this field is not defined, image entries will appear under 'images.custom'.
	// +optional
	Name string `json:"name,omitempty" yaml:"name,omitempty"`
	// Key is an optional name of the field within 'path' that will be used to uniquely identify an image.
	// Note - this field MUST be unique.
	// +optional
	Key string `json:"key,omitempty" yaml:"key,omitempty"`
	// JMESPath is an optional JMESPath expression to apply to the image value.
	// This is useful when the extracted image begins with a prefix like 'docker://'.
	// The 'trim_prefix' function may be used to trim the prefix: trim_prefix(@, 'docker://').
	// Note - Image digest mutation may not be used when applying a JMESPAth to an image.
	// +optional
	JMESPath string `json:"jmesPath,omitempty" yaml:"jmesPath,omitempty"`
}

// VerificationRules is a set of VerificationPolicy
type VerificationRules []VerificationRule

// VerificationRule is a rule against which images are validated.
type VerificationRule struct {
	// ImageReferences is a list of matching image reference patterns. At least one pattern in the
	// list must match the image for the rule to apply. Each image reference consists of a registry
	// address, repository, image, and tag (defaults to latest). Wildcards ('*' and '?') are allowed.
	ImageReferences string `json:"imageReferences"`

	// Cosign is an array of attributes used to verify cosign signatures
	// +optional
	Cosign []*Cosign `json:"cosign,omitempty"`

	// Notary is an array of attributes used to verify notary signatures
	// +optional
	Notary []*Notary `json:"notary,omitempty"`
}

// Cosign is a set of attributes used to verify cosign signatures
type Cosign struct {
	// +optional
	Key *Key `json:"key,omitempty"`
	// +optional
	Keyless *Keyless `json:"keyless,omitempty"`
	// +optional
	Certificate *Certificate `json:"certificate,omitempty"`
	// +optional
	Rekor *Rekor `json:"rekor,omitempty"`
	// +optional
	CTLog *CTLog `json:"ctlog,omitempty"`
	// +optional
	SignatureAlgorithm string `json:"signatureAlgorithm,omitempty"`
	// +optional
	Repository string `json:"repository,omitempty"`
	// +optional
	IgnoreTlog bool `json:"ignoreTlog"`
	// +optional
	IgnoreSCT bool `json:"ignoreSCT"`
	// +optional
	TSACertChain string `json:"tsaCertChain"`
	// +optional
	InToToAttestations []*Attestation `json:"intotoAttestations,omitempty"`
}

type Key struct {
	// +optional
	PublicKey string `json:"publicKey"`
}

type Keyless struct {
	// +optional
	Issuer string `json:"issuer"`
	// +optional
	Subject string `json:"subject"`
	// +optional
	Root string `json:"root"`
}

type Certificate struct {
	// +optional
	Cert string `json:"cert"`
	// +optional
	CertChain string `json:"certChain"`
}

type Rekor struct {
	// +optional
	URL string `json:"url"`
	// +optional
	PubKey string `json:"pubKey"`
}

type CTLog struct {
	// +optional
	PubKey string `json:"pubKey"`
}

// Notary is a set of attributes used to verify notary signatures
type Notary struct {
	Certs string `json:"certs"`
	// +optional
	Attestations []*Attestation `json:"attestations"`
}

type Attestation struct {
	// +optional
	Type string `json:"type"`
	// Conditions are used to verify attributes within a Predicate. If no Conditions are specified
	// the attestation check is satisfied as long there are predicates that match the predicate type.
	// +optional
	Conditions []kyvernov1.AnyAllConditions `json:"conditions,omitempty" yaml:"conditions,omitempty"`
}

func (v *VerificationRule) Validate() error {
	for _, v := range v.Cosign {
		if v != nil {
			var attestorAlreadyExists bool
			if v.Key != nil {
				if attestorAlreadyExists {
					return errMultipleAttestor
				}
				attestorAlreadyExists = true
			}
			if v.Keyless != nil {
				if attestorAlreadyExists {
					return errMultipleAttestor
				}
				attestorAlreadyExists = true
			}
			if v.Certificate != nil {
				if attestorAlreadyExists {
					return errMultipleAttestor
				}
				attestorAlreadyExists = true
			}
		}
	}
	return nil
}
