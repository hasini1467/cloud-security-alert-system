"""
AWS IoT Core MQTT Subscriber Service.
Listens for asynchronous security status messages dispatched by AWS Lambda via AWS IoT Core.
"""

import json
import logging
import os
import ssl
import threading
import time
from typing import Any, Callable, Dict, Optional

import database

logger = logging.getLogger("backend.mqtt_service")

try:
    import paho.mqtt.client as mqtt
except ImportError:
    mqtt = None

AWS_IOT_ENDPOINT = os.getenv("AWS_IOT_ENDPOINT", "")
MQTT_TOPIC = os.getenv("MQTT_TOPIC", "s3/security/status")
_local = os.path.join(os.path.dirname(os.path.abspath(__file__)), "certs")
CERTS_DIR = "/etc/secrets" if os.path.exists("/etc/secrets/certificate.pem.crt") else _local


class MqttService:
    """Manages MQTT subscription to AWS IoT Core topic."""

    def __init__(self, on_status_received: Optional[Callable[[Dict[str, Any]], None]] = None):
        self.endpoint = AWS_IOT_ENDPOINT
        self.topic = MQTT_TOPIC
        self.on_status_received = on_status_received
        self.client = None
        self._thread = None
        self._stop_event = threading.Event()
        self.is_connected = False

    def start(self) -> None:
        """Start the MQTT client thread."""
        self._thread = threading.Thread(target=self._run, name="MqttWorkerThread", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        """Stop the MQTT client thread."""
        self._stop_event.set()
        if self.client:
            try:
                self.client.disconnect()
            except Exception:
                pass

    def _run(self) -> None:
        """Connect to AWS IoT Core MQTT or wait in standby simulation mode."""
        ca_path = os.path.join(CERTS_DIR, "root-CA.crt")
        cert_path = os.path.join(CERTS_DIR, "certificate.pem.crt")
        key_path = os.path.join(CERTS_DIR, "private.pem.key")

        has_certs = os.path.exists(ca_path) and os.path.exists(cert_path) and os.path.exists(key_path)

        if not self.endpoint or not has_certs or mqtt is None:
            logger.warning("MQTT standby: endpoint set=%s | paho installed=%s | CERTS_DIR=%s",
                           bool(self.endpoint), mqtt is not None, CERTS_DIR)
            for _p in (ca_path, cert_path, key_path):
                logger.warning("MQTT cert check: %s exists=%s", _p, os.path.exists(_p))
            logger.warning("MQTT %s contents: %s", CERTS_DIR,
                           os.listdir(CERTS_DIR) if os.path.isdir(CERTS_DIR) else "folder missing")
            while not self._stop_event.is_set():
                time.sleep(1)
            return

        logger.info("Configuring TLS connection to AWS IoT Core: %s (Topic: %s)", self.endpoint, self.topic)
        try:
            self.client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION1,
                                      client_id="DockerBackendSecurityMonitor",
                                      protocol=mqtt.MQTTv311)
            self.client.tls_set(
                ca_certs=ca_path,
                certfile=cert_path,
                keyfile=key_path,
                tls_version=ssl.PROTOCOL_TLSv1_2,
            )

            def on_connect(client, userdata, flags, rc):
                if rc == 0:
                    logger.info("Connected to AWS IoT Core broker successfully!")
                    self.is_connected = True
                    client.subscribe(self.topic, qos=1)
                else:
                    logger.error("Failed to connect to AWS IoT Core. Return code: %d", rc)

            def on_message(client, userdata, msg):
                try:
                    payload = json.loads(msg.payload.decode("utf-8"))
                    logger.info("Received MQTT message on '%s': %s", msg.topic, payload)

                    # Persist into SQLite
                    status = payload.get("status", "SECURE")
                    trigger = payload.get("trigger_type", "IOT_CORE")
                    total = payload.get("total_buckets", 0)
                    public_count = payload.get("public_buckets", 0)
                    findings = payload.get("findings", [])

                    database.save_scan(
                        status=status,
                        trigger_type=trigger,
                        total_buckets=total,
                        public_buckets=public_count,
                        findings=findings,
                        raw_payload=payload,
                    )

                    if self.on_status_received:
                        self.on_status_received(payload)
                except Exception as exc:
                    logger.error("Error processing incoming MQTT message: %s", exc)

            self.client.on_connect = on_connect
            self.client.on_message = on_message

            self.client.connect(self.endpoint, port=8883, keepalive=60)
            self.client.loop_start()

            while not self._stop_event.is_set():
                time.sleep(1)

            self.client.loop_stop()
        except Exception as exc:
            logger.error("MQTT client connection error: %s", exc)