"""
AWS Service Interface for Cloud Security Alert System.
Invokes AWS Lambda security scanner or falls back to local laptop simulation.
"""

import json
import logging
import os
from typing import Any, Dict

logger = logging.getLogger("backend.aws_service")

# Load environment configuration
AWS_REGION = os.getenv("AWS_REGION", "ap-south-1")
LAMBDA_FUNCTION_NAME = os.getenv("LAMBDA_FUNCTION_NAME", "s3-security-scanner")
SIMULATION_MODE = os.getenv("SIMULATION_MODE", "true").lower() in ("true", "1", "yes")

try:
    import boto3
    from botocore.exceptions import ClientError
except ImportError:
    boto3 = None
    ClientError = Exception


class AwsSecurityService:
    """Manages cloud scanning triggers and AWS Lambda communication."""

    def __init__(self):
        self.region = AWS_REGION
        self.lambda_function = LAMBDA_FUNCTION_NAME
        self.simulation_mode = SIMULATION_MODE
        self.lambda_client = None

        if boto3 is not None and not self.simulation_mode:
            try:
                self.lambda_client = boto3.client("lambda", region_name=self.region)
                logger.info("Initialized AWS Lambda client for region: %s", self.region)
            except Exception as exc:
                logger.warning("Could not initialize boto3 Lambda client: %s. Enabling simulation mode.", exc)
                self.simulation_mode = True
        else:
            self.simulation_mode = True

    def trigger_scan(self, trigger_type: str = "MANUAL") -> Dict[str, Any]:
        """
        Trigger an S3 security scan.
        If live AWS Lambda is available, invokes it; otherwise performs simulated scan.
        """
        if not self.simulation_mode and self.lambda_client is not None:
            try:
                logger.info("Invoking AWS Lambda function '%s' (%s)...", self.lambda_function, trigger_type)
                response = self.lambda_client.invoke(
                    FunctionName=self.lambda_function,
                    InvocationType="RequestResponse",
                    Payload=json.dumps({"trigger": trigger_type}),
                )
                payload_raw = response["Payload"].read().decode("utf-8")
                result = json.loads(payload_raw)
                logger.info("Lambda response: %s", result)
                return result
            except Exception as exc:
                logger.error("Failed to invoke AWS Lambda (%s). Falling back to simulation.", exc)

        # Fallback local simulation
        return self._local_simulation_scan(trigger_type)

    def _local_simulation_scan(self, trigger_type: str) -> Dict[str, Any]:
        """Provides local simulated audit responses for laptop evaluation."""
        return {
            "status": "SECURE",
            "total_buckets": 3,
            "public_buckets": 0,
            "findings": [],
            "trigger_type": trigger_type,
            "mode": "LOCAL_SIMULATION",
            "message": "Local laptop simulation completed. All monitored buckets are secure.",
        }

    def simulate_threat(self) -> Dict[str, Any]:
        """Simulate an active public bucket exposure for testing the red LED & alert."""
        return {
            "status": "SECURITY_RISK",
            "total_buckets": 3,
            "public_buckets": 1,
            "findings": [
                {
                    "bucket": "customer-records-demo",
                    "reasons": [
                        "Bucket ACL grants public access to AllUsers (READ)",
                        "Block Public Access is disabled on bucket",
                    ],
                }
            ],
            "trigger_type": "LOCAL_SIMULATION_THREAT",
            "mode": "LOCAL_SIMULATION",
            "message": "Threat simulated: 1 bucket exposed to public internet.",
        }

    def simulate_secure(self) -> Dict[str, Any]:
        """Simulate remediation back to a secure green state."""
        return {
            "status": "SECURE",
            "total_buckets": 3,
            "public_buckets": 0,
            "findings": [],
            "trigger_type": "LOCAL_SIMULATION_REMEDIATED",
            "mode": "LOCAL_SIMULATION",
            "message": "Remediation verified: S3 Block Public Access restored.",
        }
