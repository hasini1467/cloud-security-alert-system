"""
Backend Flask Application for Cloud Security Alert System.
Provides REST API for frontend dashboard, manages SQLite database, and runs MQTT subscriber.
Flask also serves the frontend HTML/CSS/JS (single-container deployment for Render).
"""

import logging
import os
from flask import Flask, jsonify, request, render_template, send_from_directory
from flask_cors import CORS

import database
from aws_service import AwsSecurityService
from mqtt_service import MqttService

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] [%(levelname)s] [backend]: %(message)s"
)
logger = logging.getLogger("backend.app")

app = Flask(__name__, static_folder='static', template_folder='templates')
CORS(app)

PORT = int(os.getenv("PORT", "5000"))

# Initialize SQLite database
database.init_db()

# Initialize AWS Service and MQTT Service
aws_service = AwsSecurityService()
mqtt_service = MqttService()
mqtt_service.start()
logger.info("Database initialized & MQTT listener launched.")


# ─── Frontend Routes ───────────────────────────────────────

@app.route("/", methods=["GET"])
def index():
    """Serve the frontend dashboard."""
    return render_template("index.html")


@app.route("/static/<path:filename>")
def serve_static(filename):
    """Serve static files (CSS, JS)."""
    return send_from_directory("static", filename)


# ─── API Routes ────────────────────────────────────────────

@app.route("/api/status", methods=["GET"])
def get_status():
    """Return the most recent security scan result."""
    latest = database.get_latest_status()
    mode = "LOCAL_SIMULATION" if aws_service.simulation_mode else "AWS_LIVE"

    if not latest:
        return jsonify({
            "status": "SECURE",
            "total_buckets": 0,
            "public_buckets": 0,
            "findings": [],
            "trigger_type": "INITIALIZING",
            "scanned_at": None,
            "mode": mode,
        }), 200

    return jsonify({
        "status": latest["status"],
        "total_buckets": latest["total_buckets"],
        "public_buckets": latest["public_buckets"],
        "findings": latest["findings"],
        "trigger_type": latest["trigger_type"],
        "scanned_at": latest["timestamp"],
        "mode": mode,
    }), 200


@app.route("/api/scan", methods=["POST"])
def manual_scan():
    """Trigger manual security scan (invokes AWS Lambda or local simulation)."""
    data = request.get_json(silent=True) or {}
    trigger_type = data.get("trigger", "MANUAL")

    result = aws_service.trigger_scan(trigger_type=trigger_type)

    status = result.get("status", "SECURE")
    total = result.get("total_buckets", 0)
    public_count = result.get("public_buckets", 0)
    findings = result.get("findings", [])

    # Persist in SQLite
    record_id = database.save_scan(
        status=status,
        trigger_type=trigger_type,
        total_buckets=total,
        public_buckets=public_count,
        findings=findings,
        raw_payload=result,
    )
    logger.info("Saved manual scan #%d with status: %s", record_id, status)

    latest = database.get_latest_status()
    latest["mode"] = "LOCAL_SIMULATION" if aws_service.simulation_mode else "AWS_LIVE"
    latest["scanned_at"] = latest["timestamp"]
    return jsonify(latest), 200


@app.route("/api/history", methods=["GET"])
def get_history():
    """Return past scan history from SQLite database."""
    history = database.get_scan_history(limit=50)
    return jsonify(history), 200


@app.route("/api/simulate-threat", methods=["POST"])
def simulate_threat():
    """Simulate public bucket exposure for testing the red LED & alert workflow."""
    result = aws_service.simulate_threat()
    database.save_scan(
        status=result["status"],
        trigger_type=result["trigger_type"],
        total_buckets=result["total_buckets"],
        public_buckets=result["public_buckets"],
        findings=result["findings"],
        raw_payload=result,
    )
    latest = database.get_latest_status()
    latest["mode"] = "LOCAL_SIMULATION"
    latest["scanned_at"] = latest["timestamp"]
    return jsonify(latest), 200


@app.route("/api/simulate-secure", methods=["POST"])
def simulate_secure():
    """Simulate remediation back to secure green LED state."""
    result = aws_service.simulate_secure()
    database.save_scan(
        status=result["status"],
        trigger_type=result["trigger_type"],
        total_buckets=result["total_buckets"],
        public_buckets=result["public_buckets"],
        findings=result["findings"],
        raw_payload=result,
    )
    latest = database.get_latest_status()
    latest["mode"] = "LOCAL_SIMULATION"
    latest["scanned_at"] = latest["timestamp"]
    return jsonify(latest), 200


@app.route("/api/health", methods=["GET"])
def health_check():
    """Docker health check endpoint."""
    return jsonify({
        "status": "healthy",
        "service": "backend",
        "database": "sqlite_connected"
    }), 200


if __name__ == "__main__":
    logger.info("Starting Backend server on port %d...", PORT)
    try:
        import waitress
        waitress.serve(app, host="0.0.0.0", port=PORT, threads=4)
    except ImportError:
        app.run(host="0.0.0.0", port=PORT, debug=False)
