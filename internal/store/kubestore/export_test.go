package kubestore

import (
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/trace"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// NewWithTelemetry is New with explicit OTel providers.
func NewWithTelemetry(c client.Client, namespace string, tp trace.TracerProvider, mp metric.MeterProvider) *Store {
	s := New(c, namespace)
	s.tel = newTelemetry(tp, mp)
	return s
}
