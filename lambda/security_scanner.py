"""
AWS Lambda Security Scanner Function.
Audits Amazon S3 bucket permissions, publishes MQTT status to AWS IoT Core,
and dispatches email alerts through Amazon SNS.
"""

import json
import logging
import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Tuple

import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger()
logger.setLevel(logging.INFO)

AWS_REGION = os.getenv("AWS_REGION", "ap-south-1")
SNS_TOPIC_ARN = os.getenv("SNS_TOPIC_ARN", "")
IOT_TOPIC = os.getenv("IOT_TOPIC", "s3/security/status")

s3_client = boto3.client("s3", region_name=AWS_REGION)
sns_client = boto3.client("sns", region_name=AWS_REGION)
iot_data_client = boto3.client("iot-data", region_name=AWS_REGION)

PUBLIC_GROUPS = {
    "http://acs.amazonaws.com/groups/global/AllUsers",
    "http://acs.amazonaws.com/groups/global/AuthenticatedUsers",
    "https://acs.amazonaws.com/groups/global/AllUsers",
    "https://acs.amazonaws.com/groups/global/AuthenticatedUsers",
}


def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """
    AWS Lambda handler entry point.
    Triggered manually by Flask backend or scheduled by Amazon EventBridge.
    """
    trigger_type = event.get("trigger", "SCHEDULED_EVENTBRIDGE")
    logger.info("Starting S3 security audit scan. Trigger type: %s", trigger_type)

    findings, total_buckets, errors = scan_all_s3_buckets()
    public_count = len(findings)
    status = "SECURITY_RISK" if public_count > 0 else "SECURE"

    now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    payload = {
        "status": status,
        "trigger_type": trigger_type,
        "total_buckets": total_buckets,
        "public_buckets": public_count,
        "findings": findings,
        "errors": errors,
        "scanned_at": now_iso,
    }

    # 1. Publish to AWS IoT Core MQTT broker
    publish_to_iot_core(payload)

    # 2. Dispatch Amazon SNS email alert if any bucket is publicly exposed
    if status == "SECURITY_RISK" and SNS_TOPIC_ARN:
        send_sns_alert(findings, now_iso)

    return payload


def scan_all_s3_buckets() -> Tuple[List[Dict[str, Any]], int, List[str]]:
    """Scan all S3 buckets for public access exposures."""
    findings: List[Dict[str, Any]] = []
    errors: List[str] = []

    try:
        response = s3_client.list_buckets()
        buckets = response.get("Buckets", [])
    except Exception as exc:
        logger.error("Failed to list S3 buckets: %s", exc)
        return [], 0, [str(exc)]

    total_count = len(buckets)

    for b in buckets:
        bname = b.get("Name")
        if not bname:
            continue

        reasons = audit_bucket(bname)
        if reasons:
            findings.append({"bucket": bname, "reasons": reasons})

    return findings, total_count, errors


def audit_bucket(bucket_name: str) -> List[str]:
    """Inspect bucket Public Access Block, ACLs, and Bucket Policy."""
    reasons: List[str] = []

    # 1. Public Access Block
    pab = {
        "BlockPublicAcls": False,
        "IgnorePublicAcls": False,
        "BlockPublicPolicy": False,
        "RestrictPublicBuckets": False,
    }
    try:
        pab_res = s3_client.get_bucket_public_access_block(Bucket=bucket_name)
        cfg = pab_res.get("PublicAccessBlockConfiguration", {})
        pab["IgnorePublicAcls"] = bool(cfg.get("IgnorePublicAcls", False))
        pab["RestrictPublicBuckets"] = bool(cfg.get("RestrictPublicBuckets", False))
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        if code not in ("NoSuchPublicAccessBlockConfiguration", "NoSuchPublicAccessBlock"):
            logger.warning("Error fetching PAB for %s: %s", bucket_name, exc)

    # 2. Bucket ACL
    if not pab["IgnorePublicAcls"]:
        try:
            acl_res = s3_client.get_bucket_acl(Bucket=bucket_name)
            for grant in acl_res.get("Grants", []):
                uri = grant.get("Grantee", {}).get("URI", "")
                perm = grant.get("Permission", "UNKNOWN")
                if uri in PUBLIC_GROUPS or uri.endswith("/AllUsers") or uri.endswith("/AuthenticatedUsers"):
                    grp = "AllUsers" if "AllUsers" in uri else "AuthenticatedUsers"
                    reasons.append(f"Bucket ACL grants public access to {grp} ({perm})")
        except Exception as exc:
            logger.warning("Could not check ACL for %s: %s", bucket_name, exc)

    # 3. Bucket Policy
    if not pab["RestrictPublicBuckets"]:
        try:
            pol_res = s3_client.get_bucket_policy(Bucket=bucket_name)
            pol_doc = json.loads(pol_res.get("Policy", "{}"))
            stmts = pol_doc.get("Statement", [])
            if isinstance(stmts, dict):
                stmts = [stmts]

            for s in stmts:
                if s.get("Effect") == "Allow":
                    principal = s.get("Principal")
                    condition = s.get("Condition")

                    is_wildcard = (
                        principal == "*"
                        or (isinstance(principal, dict) and principal.get("AWS") == "*")
                        or (isinstance(principal, dict) and "*" in principal.get("AWS", []))
                    )
                    has_condition = bool(condition and len(condition) > 0)

                    if is_wildcard and not has_condition:
                        sid = s.get("Sid", "UnnamedStatement")
                        reasons.append(f"Bucket policy has open wildcard Allow statement (Sid: {sid})")
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code != "NoSuchBucketPolicy":
                logger.warning("Policy check error on %s: %s", bucket_name, exc)

    return reasons


def publish_to_iot_core(payload: Dict[str, Any]) -> None:
    """Publish the audit result to AWS IoT Core MQTT broker."""
    try:
        logger.info("Publishing status payload to IoT topic: %s", IOT_TOPIC)
        iot_data_client.publish(
            topic=IOT_TOPIC,
            qos=1,
            payload=json.dumps(payload),
        )
        logger.info("Successfully published message to AWS IoT Core.")
    except Exception as exc:
        logger.warning("Could not publish to AWS IoT Core (check IoT endpoint / permissions): %s", exc)


def send_sns_alert(findings: List[Dict[str, Any]], scanned_at: str) -> None:
    """Send critical security notification email via Amazon SNS."""
    subject = f"SECURITY ALERT: {len(findings)} Insecure S3 Bucket(s) Detected!"
    details = ""
    for f in findings:
        details += f"\n- Bucket: {f['bucket']}\n"
        for r in f["reasons"]:
            details += f"    * {r}\n"

    message = (
        f"AWS CLOUD SECURITY ALERT\n"
        f"========================\n"
        f"Timestamp: {scanned_at}\n"
        f"Region   : {AWS_REGION}\n\n"
        f"Identified Public S3 Buckets:{details}\n"
        f"Immediate Action Required:\n"
        f"Enable Amazon S3 Block Public Access or remediate bucket policy/ACL grants.\n"
    )

    try:
        sns_client.publish(
            TopicArn=SNS_TOPIC_ARN,
            Subject=subject[:100],
            Message=message,
        )
        logger.info("Published security alert to SNS topic: %s", SNS_TOPIC_ARN)
    except Exception as exc:
        logger.error("Failed to send SNS alert: %s", exc)
