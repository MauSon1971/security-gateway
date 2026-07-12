"""VKF · OpenTelemetry bootstrap.

Configures OTLP exporter to Jaeger (running on host, port 4317 gRPC) and
instruments FastAPI + psycopg2 + logging.

Enabled only when env VKF_OTEL_ENABLED=1 (defaults on if Jaeger present).
Falls back silently to no-op if OTel deps missing.
"""
from __future__ import annotations

import logging
import os

LOG = logging.getLogger("vkf.otel")


def init_tracing(app, service_name: str = "vkf-guard") -> bool:
    """Initialize OpenTelemetry tracing. Returns True if set up, False if skipped."""
    if os.environ.get("VKF_OTEL_ENABLED", "1") != "1":
        LOG.info("OTel disabled via VKF_OTEL_ENABLED=0")
        return False

    try:
        from opentelemetry import trace
        from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
        from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
        from opentelemetry.instrumentation.psycopg2 import Psycopg2Instrumentor
        from opentelemetry.sdk.resources import Resource
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor
    except ImportError as e:
        LOG.warning("OTel packages missing (%s); tracing disabled", e)
        return False

    endpoint = os.environ.get("VKF_OTEL_ENDPOINT", "http://127.0.0.1:4317")
    resource = Resource.create(
        {
            "service.name": service_name,
            "service.namespace": "vektrun-forge",
            "service.version": os.environ.get("VKF_VERSION", "0.3.0"),
            "deployment.environment": os.environ.get("VKF_ENV", "prod"),
        }
    )
    provider = TracerProvider(resource=resource)
    provider.add_span_processor(
        BatchSpanProcessor(OTLPSpanExporter(endpoint=endpoint, insecure=True))
    )
    trace.set_tracer_provider(provider)

    FastAPIInstrumentor.instrument_app(app, excluded_urls="/metrics,/health")
    Psycopg2Instrumentor().instrument(enable_commenter=False)

    LOG.info("OTel tracing enabled → %s", endpoint)
    return True
