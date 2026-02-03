package fake

import (
	"encoding/json"
	"fmt"
	"strings"

	jsonpatch "github.com/evanphx/json-patch/v5"
	data_nais_io_v1 "github.com/nais/pgrator/pkg/api/datav1"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	dynfake "k8s.io/client-go/dynamic/fake"
	k8stesting "k8s.io/client-go/testing"
)

// This is a hack around how k8s unsafeGuesses resource plurals
func depluralized(s string) string {
	switch s {
	case "valkeies":
		return "valkeys"
	case "opensearchs", "opensearches":
		return "opensearches"
	case "unleashs":
		return "unleashes"
	case "remoteunleashs":
		return "remoteunleashes"
	case "postgreses":
		return "postgres"
	}

	return s
}

func NewDynamicClient(objs ...runtime.Object) *dynfake.FakeDynamicClient {
	scheme, err := NewScheme()
	if err != nil {
		panic(err)
	}
	newScheme := runtime.NewScheme()
	for gvk := range scheme.AllKnownTypes() {
		if newScheme.Recognizes(gvk) {
			continue
		}
		// Ensure we are always supporting unstructured objects
		// This to prevent various problems with the fake client
		if strings.HasSuffix(gvk.Kind, "List") {
			newScheme.AddKnownTypeWithName(gvk, &unstructured.UnstructuredList{})
			continue
		}
		newScheme.AddKnownTypeWithName(gvk, &unstructured.Unstructured{})
	}

	client := dynfake.NewSimpleDynamicClientWithCustomListKinds(newScheme,
		map[schema.GroupVersionResource]string{
			data_nais_io_v1.GroupVersion.WithResource("postgres"): "PostgresList",
		})

	// Add reactor for JSON Patch support
	client.PrependReactor("patch", "*", func(action k8stesting.Action) (handled bool, ret runtime.Object, err error) {
		patchAction, ok := action.(k8stesting.PatchAction)
		if !ok {
			return false, nil, nil
		}

		// Only handle JSON Patch type
		if patchAction.GetPatchType() != types.JSONPatchType {
			return false, nil, nil
		}

		// Get the existing object from the tracker
		gvr := patchAction.GetResource()
		ns := patchAction.GetNamespace()
		name := patchAction.GetName()

		obj, err := client.Tracker().Get(gvr, ns, name)
		if err != nil {
			return true, nil, err
		}

		// Get the original object as unstructured to preserve apiVersion/kind
		original, ok := obj.(*unstructured.Unstructured)
		if !ok {
			return true, nil, fmt.Errorf("expected *unstructured.Unstructured, got %T", obj)
		}

		// Convert to JSON
		objJSON, err := json.Marshal(obj)
		if err != nil {
			return true, nil, fmt.Errorf("marshaling object: %w", err)
		}

		// Apply the JSON patch
		patch, err := jsonpatch.DecodePatch(patchAction.GetPatch())
		if err != nil {
			return true, nil, fmt.Errorf("decoding patch: %w", err)
		}

		modifiedJSON, err := patch.Apply(objJSON)
		if err != nil {
			return true, nil, fmt.Errorf("applying patch: %w", err)
		}

		// Convert back to unstructured
		modified := &unstructured.Unstructured{}
		if err := json.Unmarshal(modifiedJSON, &modified.Object); err != nil {
			return true, nil, fmt.Errorf("unmarshaling modified object: %w", err)
		}

		// Preserve apiVersion and kind from original object (JSON patch may not include them)
		if modified.GetAPIVersion() == "" {
			modified.SetAPIVersion(original.GetAPIVersion())
		}
		if modified.GetKind() == "" {
			modified.SetKind(original.GetKind())
		}

		// Update the object in the tracker
		if err := client.Tracker().Update(gvr, modified, ns); err != nil {
			return true, nil, fmt.Errorf("updating object: %w", err)
		}

		return true, modified, nil
	})

	if len(objs) > 0 {
		AddObjectToDynamicClient(scheme, client, objs...)
	}

	return client
}

func AddObjectToDynamicClient(scheme *runtime.Scheme, fc *dynfake.FakeDynamicClient, objs ...runtime.Object) {
	type namespaced interface {
		GetNamespace() string
	}

	for _, obj := range objs {
		if obj.GetObjectKind().GroupVersionKind().Kind == "List" {
			list := obj.(*unstructured.Unstructured)
			ul, err := list.ToList()
			if err != nil {
				panic(err)
			}
			for _, item := range ul.Items {
				AddObjectToDynamicClient(scheme, fc, &item)
			}
			continue
		}

		gvks, _, err := scheme.ObjectKinds(obj)
		if err != nil {
			panic(err)
		}

		if len(gvks) == 0 {
			panic(fmt.Errorf("no registered kinds for %v", obj))
		}
		for _, gvk := range gvks {
			gvr, _ := meta.UnsafeGuessKindToResource(gvk)

			gvr.Resource = depluralized(gvr.Resource)
			// Get namespace from object
			ns := obj.(namespaced).GetNamespace()
			if err := fc.Tracker().Create(gvr, obj, ns); err != nil {
				panic(err)
			}
		}
	}
}
