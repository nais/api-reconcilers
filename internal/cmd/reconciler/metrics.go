package reconciler

import (
	"fmt"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/prometheus"
	"go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	semconv "go.opentelemetry.io/otel/semconv/v1.24.0"

	promClient "github.com/prometheus/client_golang/prometheus"
)

func newResource() (*resource.Resource, error) {
	return resource.Merge(resource.Default(),
		resource.NewWithAttributes(semconv.SchemaURL,
			semconv.ServiceName("api-reconcilers"),
			semconv.ServiceVersion("0.1.0"),
		))
}

func newMeterProvider() (*metric.MeterProvider, promClient.Gatherer, error) {
	res, err := newResource()
	if err != nil {
		return nil, nil, fmt.Errorf("creating resource: %w", err)
	}

	reg := promClient.NewRegistry()
	metricExporter, err := prometheus.New(
		prometheus.WithRegisterer(reg),
	)
	if err != nil {
		return nil, nil, fmt.Errorf("creating prometheus exporter: %w", err)
	}

	meterProvider := metric.NewMeterProvider(
		metric.WithResource(res),
		metric.WithReader(metricExporter),
	)

	otel.SetMeterProvider(meterProvider)
	return meterProvider, reg, nil
}
