package main

import (
	"github.com/nirmata/json-image-verification/pkg/apis/v1alpha1"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

var (
	gv                               = schema.GroupVersion{Group: "nirmata.io", Version: "v1alpha1"}
	imageVerificationPolicy_v1alpha1 = gv.WithKind("ImageVerificationPolicy")
)

func Load(path ...string) ([]*v1alpha1.ImageVerificationPolicy, error) {
	var policies []*v1alpha1.ImageVerificationPolicy
	// commenting to remove sigs.k8s.io/kubectl-validate/pkg/openapiclient dependency for cloud controller
	// for _, path := range path {
	// 	p, err := load(path)
	// 	if err != nil {
	// 		return nil, err
	// 	}
	// 	policies = append(policies, p...)
	// }
	return policies, nil
}

// func load(path string) ([]*v1alpha1.ImageVerificationPolicy, error) {
// 	var files []string
// 	err := filepath.Walk(path, func(file string, info fs.FileInfo, err error) error {
// 		if err != nil {
// 			return err
// 		}
// 		if fileinfo.IsYaml(info) {
// 			files = append(files, file)
// 		}
// 		return nil
// 	})
// 	if err != nil {
// 		return nil, err
// 	}
// 	var policies []*v1alpha1.ImageVerificationPolicy
// 	for _, path := range files {
// 		content, err := os.ReadFile(filepath.Clean(path))
// 		if err != nil {
// 			return nil, err
// 		}
// 		p, err := Parse(content)
// 		if err != nil {
// 			return nil, err
// 		}
// 		policies = append(policies, p...)
// 	}
// 	return policies, nil
// }

// func Parse(content []byte) ([]*v1alpha1.ImageVerificationPolicy, error) {
// 	documents, err := yamlutils.SplitDocuments(content)
// 	if err != nil {
// 		return nil, err
// 	}
// 	crds, err := data.Crds()
// 	if err != nil {
// 		return nil, err
// 	}
// 	loader, err := loader.New(openapiclient.NewLocalCRDFiles(crds))
// 	if err != nil {
// 		return nil, err
// 	}
// 	var policies []*v1alpha1.ImageVerificationPolicy
// 	for _, document := range documents {
// 		gvk, untyped, err := loader.Load(document)
// 		if err != nil {
// 			return nil, err
// 		}
// 		switch gvk {
// 		case imageVerificationPolicy_v1alpha1:
// 			policy, err := convert.To[v1alpha1.ImageVerificationPolicy](untyped)
// 			if err != nil {
// 				return nil, err
// 			}
// 			policies = append(policies, policy)
// 		default:
// 			return nil, fmt.Errorf("policy type not supported %s", gvk)
// 		}
// 	}
// 	return policies, nil
// }
