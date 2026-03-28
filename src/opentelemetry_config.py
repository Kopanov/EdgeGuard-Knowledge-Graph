"""
OpenTelemetry configuration
"""

import os

from opentelemetry import trace
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor, ConsoleSpanExporter


def init_tracing(
    service_name: str = "edgeguard",
    export_otlp: bool = False,
    dev_mode: bool = None,
):
    """Initialize OpenTelemetry tracing.

    Args:
        service_name: Logical name for this service in traces.
        export_otlp:  When True, also ship spans to the OTLP gRPC collector.
        dev_mode:     When True, attach a ConsoleSpanExporter so spans are
                      printed to stdout (useful during local development).
                      Defaults to the value of the ``EDGEGUARD_DEV_MODE``
                      environment variable (truthy: "1", "true", "yes").
                      In production this must be False (or the env var absent)
                      to avoid flooding stdout with multi-MB span payloads.
    """
    if dev_mode is None:
        dev_mode = os.getenv("EDGEGUARD_DEV_MODE", "").lower() in ("1", "true", "yes")

    provider = TracerProvider()

    if dev_mode:
        # Console exporter is for local development only — it writes raw span
        # JSON to stdout, which breaks structured log pipelines in production.
        provider.add_span_processor(BatchSpanProcessor(ConsoleSpanExporter()))

    if export_otlp:
        otlp_endpoint = os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://localhost:4317")
        # OTEL_EXPORTER_OTLP_INSECURE should only be "true" in local dev.
        otlp_insecure = os.getenv("OTEL_EXPORTER_OTLP_INSECURE", "false").lower() == "true"
        provider.add_span_processor(
            BatchSpanProcessor(OTLPSpanExporter(endpoint=otlp_endpoint, insecure=otlp_insecure))
        )

    trace.set_tracer_provider(provider)
    return trace.get_tracer(service_name)
