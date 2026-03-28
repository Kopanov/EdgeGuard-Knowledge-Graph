"""
NATS Client for ResilMesh Integration
Publishes and subscribes to threat intelligence
"""

import asyncio
import json
import logging
from typing import Callable, List, Optional

import nats
from nats.aio.client import Client as NATSClientConn
from nats.aio.subscription import Subscription

# OpenTelemetry imports
from opentelemetry import trace

logger = logging.getLogger(__name__)

# Initialize tracer
tracer = trace.get_tracer(__name__)


class NATSClient:
    """
    NATS Client for ResilMesh Integration.

    Publishes and subscribes to threat intelligence topics:
    - resilmesh.threats.zone.<zone_id> - Publish threat intel
    - resilmesh.alerts.zone.<zone_id> - Subscribe to alerts
    - resilmesh.indicators.zone.<zone_id> - Bidirectional indicator sharing

    Features:
    - Async/await support
    - TLS encryption support
    - Connection retry logic
    - Message callbacks
    """

    def __init__(self, servers: List[str], use_tls: bool = True):
        self.servers = servers
        self.use_tls = use_tls
        self.nc: Optional[NATSClientConn] = None
        self.subscriptions: List[Subscription] = []
        self._callbacks: dict = {}

    async def connect(self) -> bool:
        """
        Connect to NATS servers.

        Returns:
            True if connection successful, False otherwise
        """
        try:
            tls_config = None
            if self.use_tls:
                import ssl

                tls_config = ssl.create_default_context()

            self.nc = await nats.connect(
                servers=self.servers,
                tls=tls_config,
                max_reconnect_attempts=10,
                reconnect_time_wait=5,
                connect_timeout=30,
            )

            logger.info(f"[OK] Connected to NATS servers: {self.servers}")
            return True

        except Exception as e:
            logger.error(f"[ERR] Failed to connect to NATS: {e}")
            return False

    async def subscribe(self, subject: str, callback: Callable):
        """
        Subscribe to a subject pattern.

        Common patterns:
        - resilmesh.alerts.zone.* - All zone alerts
        - resilmesh.threats.zone.us-gov - Specific zone threats
        - resilmesh.indicators.> - All indicator updates

        Args:
            subject: NATS subject pattern (supports wildcards * and >)
            callback: Async callback function(msg)
        """
        with tracer.start_as_current_span("nats.subscribe") as span:
            span.set_attribute("nats.subject", subject)

            if not self.nc:
                raise RuntimeError("Not connected to NATS. Call connect() first.")

            async def message_handler(msg):
                with tracer.start_as_current_span("nats.message_handler") as handler_span:
                    handler_span.set_attribute("nats.subject", msg.subject)
                    try:
                        data = json.loads(msg.data.decode())
                        subject = msg.subject
                        # Propagate trace context if present in payload
                        trace_id = data.get("trace_id")
                        if trace_id:
                            handler_span.set_attribute("trace_id", trace_id)
                        await callback(subject, data)
                    except json.JSONDecodeError as e:
                        logger.warning(f"Failed to decode JSON from {msg.subject}: {e}")
                        handler_span.set_attribute("error", True)
                        handler_span.set_attribute("error.message", str(e))
                    except Exception as e:
                        logger.error(f"Error in message handler for {msg.subject}: {e}")
                        handler_span.set_attribute("error", True)
                        handler_span.set_attribute("error.message", str(e))

            sub = await self.nc.subscribe(subject, cb=message_handler)
            self.subscriptions.append(sub)
            self._callbacks[subject] = callback

            logger.info(f"📡 Subscribed to: {subject}")
            return sub

    async def publish(self, subject: str, payload: dict) -> bool:
        """
        Publish to a subject.

        Common subjects:
        - resilmesh.threats.zone.<zone_id> - Publish threat intelligence
        - resilmesh.alerts.zone.<zone_id> - Publish alerts
        - resilmesh.indicators.zone.<zone_id> - Share indicators

        Args:
            subject: NATS subject
            payload: Dict to serialize as JSON

        Returns:
            True if published successfully
        """
        with tracer.start_as_current_span("nats.publish") as span:
            span.set_attribute("nats.subject", subject)

            if not self.nc:
                raise RuntimeError("Not connected to NATS. Call connect() first.")

            try:
                # Add trace_id to payload for distributed tracing
                span_context = span.get_span_context()
                payload["trace_id"] = str(span_context.trace_id)
                span.set_attribute("trace_id", str(span_context.trace_id))

                data = json.dumps(payload).encode()
                await self.nc.publish(subject, data)
                span.set_attribute("payload_size_bytes", len(data))
                logger.debug(f"[PUSH] Published to {subject}: {len(data)} bytes")
                return True

            except Exception as e:
                logger.error(f"Failed to publish to {subject}: {e}")
                span.set_attribute("error", True)
                span.set_attribute("error.message", str(e))
                return False

    async def request(self, subject: str, payload: dict, timeout: float = 5.0) -> Optional[dict]:
        """
        Make a request and wait for response (request-reply pattern).

        Args:
            subject: NATS subject
            payload: Request payload
            timeout: Maximum time to wait for response

        Returns:
            Response dict or None if timeout
        """
        if not self.nc:
            raise RuntimeError("Not connected to NATS. Call connect() first.")

        try:
            data = json.dumps(payload).encode()
            response = await self.nc.request(subject, data, timeout=timeout)
            try:
                return json.loads(response.data.decode())
            except (json.JSONDecodeError, UnicodeDecodeError) as e:
                logger.error(f"Malformed response on {subject}: {e}")
                return None

        except asyncio.TimeoutError:
            logger.warning(f"Request timeout on {subject}")
            return None
        except Exception as e:
            logger.error(f"Request failed on {subject}: {e}")
            return None

    async def close(self):
        """Close all subscriptions and connections."""
        if not self.nc:
            return

        # Unsubscribe all
        for sub in self.subscriptions:
            try:
                await sub.unsubscribe()
            except Exception as e:
                logger.debug(f"Error unsubscribing: {e}")

        self.subscriptions.clear()

        # Close connection
        try:
            await self.nc.close()
            logger.info("🔌 NATS connection closed")
        except Exception as e:
            logger.warning(f"Error closing NATS connection: {e}")

        self.nc = None

    def is_connected(self) -> bool:
        """Check if connected to NATS."""
        return self.nc is not None and self.nc.is_connected

    async def flush(self):
        """Flush pending messages."""
        if self.nc:
            await self.nc.flush()


# Convenience functions for common ResilMesh patterns


async def publish_threat(zone: str, threat_data: dict, client: NATSClient) -> bool:
    """Publish a threat to a specific zone."""
    subject = f"resilmesh.threats.zone.{zone}"
    return await client.publish(subject, threat_data)


async def publish_alert(zone: str, alert_data: dict, client: NATSClient) -> bool:
    """Publish an alert to a specific zone."""
    subject = f"resilmesh.alerts.zone.{zone}"
    return await client.publish(subject, alert_data)


async def subscribe_to_zone_alerts(zone: str, callback: Callable, client: NATSClient):
    """Subscribe to alerts for a specific zone."""
    subject = f"resilmesh.alerts.zone.{zone}"
    return await client.subscribe(subject, callback)


# Example usage
async def example():
    """Example usage of NATSClient."""
    # Initialize client
    client = NATSClient(servers=["nats://localhost:4222", "nats://backup:4222"], use_tls=True)

    # Connect
    if not await client.connect():
        print("Failed to connect")
        return

    # Subscribe to alerts
    async def alert_handler(subject: str, data: dict):
        print(f"🚨 Alert from {subject}: {data}")

    await client.subscribe("resilmesh.alerts.zone.*", alert_handler)

    # Publish a threat
    threat = {
        "type": "malicious_ip",
        "value": "192.168.1.100",
        "severity": "high",
        "source": "otx",
        "timestamp": "2024-01-15T10:00:00Z",
    }
    await client.publish("resilmesh.threats.zone.us-gov", threat)

    # Keep running
    try:
        while True:
            await asyncio.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        await client.close()


if __name__ == "__main__":
    asyncio.run(example())
