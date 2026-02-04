package fake

import (
	data_nais_io_v1 "github.com/nais/pgrator/pkg/api/datav1"
	"k8s.io/apimachinery/pkg/runtime"
)

func NewScheme() (*runtime.Scheme, error) {
	scheme := runtime.NewScheme()

	funcs := []func(s *runtime.Scheme) error{
		data_nais_io_v1.AddToScheme,
	}

	for _, f := range funcs {
		if err := f(scheme); err != nil {
			return nil, err
		}
	}

	return scheme, nil
}
