package imageverifier

import (
	"context"
	"fmt"

	"github.com/go-logr/logr"
	kyvernov1 "github.com/kyverno/kyverno/api/kyverno/v1"
	"github.com/kyverno/kyverno/pkg/clients/dclient"
	"github.com/kyverno/kyverno/pkg/config"
	"github.com/kyverno/kyverno/pkg/engine/apicall"
	enginectx "github.com/kyverno/kyverno/pkg/engine/context"
	"github.com/kyverno/kyverno/pkg/engine/context/loaders"
	"github.com/kyverno/kyverno/pkg/engine/jmespath"
	"github.com/kyverno/kyverno/pkg/engine/jsonutils"
	"github.com/kyverno/kyverno/pkg/engine/variables"
	apiutils "github.com/kyverno/kyverno/pkg/utils/api"
	imageutils "github.com/kyverno/kyverno/pkg/utils/image"
	"github.com/nirmata/json-image-verification/pkg/apis/v1alpha1"
	"k8s.io/apimachinery/pkg/runtime"
)

// substitute variables

func addResourceToJsonContext(ctx enginectx.Interface, resource interface{}) error {
	data, err := jsonutils.DocumentToUntyped(resource)
	if err != nil {
		return err
	}

	err = ctx.AddVariable("resource", data)
	if err != nil {
		return err
	}

	return nil
}

func addContextEntriesToJsonContext(ctx enginectx.Interface, client dclient.Interface, jp jmespath.Interface, entries *[]v1alpha1.ContextEntry) error {
	for _, entry := range *entries {
		if entry.Variable != nil {
			ctxEntry := kyvernov1.ContextEntry{
				Variable: entry.Variable,
			}
			ldr := loaders.NewVariableLoader(logr.Discard(), ctxEntry, ctx, jp)
			err := ldr.LoadData()
			if err != nil {
				return err
			}
		} else if entry.APICall != nil {
			ctxEntry := kyvernov1.ContextEntry{
				APICall: entry.APICall,
			}
			ldr := loaders.NewAPILoader(context.TODO(), logr.Discard(), ctxEntry, ctx, jp, client, apicall.APICallConfiguration{})
			err := ldr.LoadData()
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func addImagesToJsonContext(ctx enginectx.Interface, images map[string]string) error {
	infos := map[string]map[string]apiutils.ImageInfo{}
	infos["containers"] = make(map[string]apiutils.ImageInfo)

	for k, v := range images {
		if imageInfo, err := imageutils.GetImageInfo(v, config.NewDefaultConfiguration(false)); err != nil {
			return fmt.Errorf("invalid image '%s' (%s)", v, err.Error())
		} else {
			infos["containers"][k] = apiutils.ImageInfo{
				ImageInfo: *imageInfo,
				Pointer:   k,
			}
		}
	}
	utm, err := convertImagesToUnstructured(infos)
	if err != nil {
		return err
	}

	err = ctx.AddVariable("images", utm)
	if err != nil {
		return err
	}

	return nil
}

func substituteVariablesInRule(rule *v1alpha1.ImageVerificationRule, jsonCtx enginectx.EvalInterface) (*v1alpha1.ImageVerificationRule, error) {
	ruleCopy := rule.DeepCopy()
	for i := range ruleCopy.Rules {
		if ruleCopy.Rules[i].Cosign != nil {
			for j := range ruleCopy.Rules[i].Cosign {
				if ruleCopy.Rules[i].Cosign[j].InToToAttestations != nil {
					for k := range ruleCopy.Rules[i].Cosign[j].InToToAttestations {
						ruleCopy.Rules[i].Cosign[j].InToToAttestations[k].Conditions = nil
					}
				}
			}
		}

		if ruleCopy.Rules[i].Notary != nil {
			for j := range ruleCopy.Rules[i].Notary {
				if ruleCopy.Rules[i].Notary[j].Attestations != nil {
					for k := range ruleCopy.Rules[i].Notary[j].Attestations {
						ruleCopy.Rules[i].Notary[j].Attestations[k].Conditions = nil
					}
				}
			}
		}

		if ruleCopy.Rules[i].ExternalService != nil {
			for j := range ruleCopy.Rules[i].ExternalService {
				if ruleCopy.Rules[i].ExternalService[j] != nil {
					ruleCopy.Rules[i].ExternalService[j].Conditions = nil
				}
			}
		}
	}

	for i := range ruleCopy.Rules {
		if ruleCopy.Rules[i].Cosign != nil {
			for j := range ruleCopy.Rules[i].Cosign {
				if ruleCopy.Rules[i].Cosign[j].InToToAttestations != nil {
					for k := range ruleCopy.Rules[i].Cosign[j].InToToAttestations {
						ruleCopy.Rules[i].Cosign[j].InToToAttestations[k].Conditions = rule.Rules[i].Cosign[j].InToToAttestations[k].Conditions
					}
				}
			}
		}
		var err error
		ruleCopy, err = variables.SubstituteAllInType(logr.Discard(), jsonCtx, ruleCopy)
		if err != nil {
			return nil, err
		}

		if ruleCopy.Rules[i].Notary != nil {
			for j := range ruleCopy.Rules[i].Notary {
				if ruleCopy.Rules[i].Notary[j].Attestations != nil {
					for k := range ruleCopy.Rules[i].Notary[j].Attestations {
						ruleCopy.Rules[i].Notary[j].Attestations[k].Conditions = rule.Rules[i].Notary[j].Attestations[k].Conditions
					}
				}
			}
		}

		if ruleCopy.Rules[i].ExternalService != nil {
			for j := range ruleCopy.Rules[i].ExternalService {
				if ruleCopy.Rules[i].ExternalService[j] != nil {
					ruleCopy.Rules[i].ExternalService[j].Conditions = rule.Rules[i].ExternalService[j].Conditions
				}
			}
		}
	}

	return ruleCopy, nil
}

func convertImagesToUnstructured(images map[string]map[string]apiutils.ImageInfo) (map[string]interface{}, error) {
	results := map[string]interface{}{}
	for containerType, v := range images {
		imgMap := map[string]interface{}{}
		for containerName := range v {
			imageInfo := v[containerName]
			img, err := toUnstructured(&imageInfo.ImageInfo)
			if err != nil {
				return nil, err
			}

			var pointer interface{} = imageInfo.Pointer
			img["jsonPointer"] = pointer

			imgMap[containerName] = img
		}

		results[containerType] = imgMap
	}

	return results, nil
}

// toUnstructured converts a struct with JSON tags to a map[string]interface{}
func toUnstructured(typedStruct interface{}) (map[string]interface{}, error) {
	converter := runtime.DefaultUnstructuredConverter
	u, err := converter.ToUnstructured(typedStruct)
	return u, err
}
