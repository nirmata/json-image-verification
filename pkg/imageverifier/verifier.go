package imageverifier

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/go-logr/logr"
	kyvernov1 "github.com/kyverno/kyverno/api/kyverno/v1"
	"github.com/kyverno/kyverno/ext/wildcard"
	"github.com/kyverno/kyverno/pkg/clients/dclient"
	"github.com/kyverno/kyverno/pkg/cosign"
	"github.com/kyverno/kyverno/pkg/engine/apicall"
	enginecontext "github.com/kyverno/kyverno/pkg/engine/context"
	"github.com/kyverno/kyverno/pkg/engine/jmespath"
	"github.com/kyverno/kyverno/pkg/engine/variables"
	"github.com/kyverno/kyverno/pkg/images"
	"github.com/kyverno/kyverno/pkg/notary"
	"github.com/nirmata/json-image-verification/pkg/apis/v1alpha1"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

type imageVerifier struct {
	count          int
	client         dclient.Interface
	rules          v1alpha1.VerificationRules
	cosignVerifier images.ImageVerifier
	notaryVerifier images.ImageVerifier
	jsonCtx        enginecontext.Interface
	jp             jmespath.Interface
}

func NewVerifier(rules v1alpha1.VerificationRules, client dclient.Interface, jsonCtx enginecontext.Interface, jp jmespath.Interface, count int) *imageVerifier {
	if count <= 0 { // either not defined or illegal value
		count = len(rules)
	}
	return &imageVerifier{
		jp:             jp,
		client:         client,
		jsonCtx:        jsonCtx,
		count:          count,
		rules:          rules,
		cosignVerifier: cosign.NewVerifier(),
		notaryVerifier: notary.NewVerifier(),
	}
}

func (i *imageVerifier) Verify(image string) VerificationResult {
	verificationResult := VerificationResult{
		VerificationResponses: make([]VerificationResponse, len(i.rules)),
		Image:                 image,
	}
	passedCount := 0
	failedCount := 0
	skippedCount := 0

	for idx, policy := range i.rules {
		verificationResp := VerificationResponse{
			VerificationRule: policy,
			Failures:         make([]error, 0),
		}
		if !wildcard.Match(policy.ImageReferences, image) {
			skippedCount += 1
			continue
		}

		for _, cosignPolicy := range policy.Cosign {
			if cosignPolicy == nil {
				continue
			}
			err := i.cosignVerification(cosignPolicy, image)
			if err != nil {
				verificationResp.Failures = append(verificationResp.Failures, err)
				continue
			}
		}

		for _, notaryPolicy := range policy.Notary {
			if notaryPolicy == nil {
				continue
			}

			err := i.notaryVerification(notaryPolicy, image)
			if err != nil {
				verificationResp.Failures = append(verificationResp.Failures, err)
				continue
			}
		}

		for _, externalPolicy := range policy.ExternalService {
			if externalPolicy == nil {
				continue
			}

			err := i.externalServiceVerification(externalPolicy, image)
			if err != nil {
				verificationResp.Failures = append(verificationResp.Failures, err)
				continue
			}
		}

		if len(verificationResp.Failures) == 0 {
			passedCount += 1
		} else {
			failedCount += 1
		}
		verificationResult.VerificationResponses[idx] = verificationResp
	}

	if passedCount >= i.count {
		verificationResult.VerificationOutcome = PASS
	} else if passedCount == 0 && failedCount == 0 && skippedCount > 0 { // all skips
		verificationResult.VerificationOutcome = SKIP
	} else {
		verificationResult.VerificationOutcome = FAIL
	}

	return verificationResult
}

func (i *imageVerifier) cosignVerification(pol *v1alpha1.Cosign, image string) error {
	opts, err := cosignVerificationOpts(pol, image)
	if err != nil {
		return err
	}

	_, err = i.cosignVerifier.VerifySignature(context.TODO(), *opts)
	if err != nil {
		return err
	}

	for _, att := range pol.InToToAttestations {
		if att == nil {
			continue
		}

		o := *opts
		o.Type = att.Type
		_, err := i.cosignVerifier.FetchAttestations(context.Background(), o)
		if err != nil {
			return err
		}
	}
	return nil
}

func (i *imageVerifier) notaryVerification(pol *v1alpha1.Notary, image string) error {
	opts, err := notaryVerificationOpts(pol, image)
	if err != nil {
		return err
	}

	_, err = i.notaryVerifier.VerifySignature(context.Background(), *opts)
	if err != nil {
		return err
	}

	for _, att := range pol.Attestations {
		if att == nil {
			continue
		}

		o := *opts
		o.Type = att.Type
		resp, err := i.notaryVerifier.FetchAttestations(context.Background(), o)
		if err != nil {
			return err
		}
		val, msg, err := i.verifyAttestationConditions(att.Conditions, resp)
		if err != nil {
			return fmt.Errorf("failed to check attestations: %w", err)
		}
		if !val {
			return fmt.Errorf("attestation checks failed for %s and predicate %s: %s", image, att.Type, msg)
		}
	}
	return nil
}

func (i *imageVerifier) externalServiceVerification(pol *v1alpha1.ExternalService, image string) error {
	executor, err := apicall.New(
		logr.Discard(),
		i.jp,
		kyvernov1.ContextEntry{
			APICall: pol.APICall,
		},
		i.jsonCtx,
		i.client,
		apicall.APICallConfiguration{},
	)
	if err != nil {
		return nil
	}

	data, err := executor.Execute(context.TODO(), pol.APICall)
	if err != nil {
		return err
	}

	var jsonData interface{}
	err = json.Unmarshal(data, &jsonData)
	if err != nil {
		return err
	}

	dataMap := make(map[string]interface{})
	if m, ok := jsonData.(map[string]interface{}); ok {
		dataMap = m
	} else {
		dataMap["response"] = jsonData
	}

	i.jsonCtx.Checkpoint()
	defer i.jsonCtx.Restore()
	if err := enginecontext.AddJSONObject(i.jsonCtx, dataMap); err != nil {
		return fmt.Errorf("failed to add response to the context: %w", err)
	}

	c, err := variables.SubstituteAllInConditions(logr.Discard(), i.jsonCtx, pol.Conditions)
	if err != nil {
		return fmt.Errorf("failed to substitute variables in attestation conditions: %w", err)
	}

	val, msg, err := variables.EvaluateAnyAllConditions(logr.Discard(), i.jsonCtx, c)
	if err != nil {
		return fmt.Errorf("failed to verify image: %w", err)
	}
	if !val {
		return fmt.Errorf("verification checks failed for %s: %s", image, msg)
	}

	return nil
}

func (i *imageVerifier) verifyAttestationConditions(conditions []kyvernov1.AnyAllConditions, resp *images.Response) (bool, string, error) {
	if len(conditions) == 0 {
		return true, "", nil
	}
	for _, s := range resp.Statements {
		i.jsonCtx.Checkpoint()
		defer i.jsonCtx.Restore()
		logger := log.Log
		predicate, ok := s["predicate"].(map[string]interface{})
		if !ok {
			return false, "", fmt.Errorf("failed to extract predicate from statement: %v", s)
		}
		if err := enginecontext.AddJSONObject(i.jsonCtx, predicate); err != nil {
			return false, "", fmt.Errorf("failed to add Statement to the context %v: %w", s, err)
		}
		c, err := variables.SubstituteAllInConditions(logger, i.jsonCtx, conditions)
		if err != nil {
			return false, "", fmt.Errorf("failed to substitute variables in attestation conditions: %w", err)
		}
		val, msg, err := variables.EvaluateAnyAllConditions(logger, i.jsonCtx, c)
		if !val || err != nil {
			return val, msg, err
		}
	}
	return true, "", nil
}
