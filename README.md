# Cloud Security Alert System (Product 8)
## Docker-based AWS S3 Security Monitoring and Alert System

A complete cloud security auditing and virtual IoT monitoring solution. The system continuously scans Amazon S3 buckets for public access vulnerabilities, dispatches real-time alerts via **AWS IoT Core (MQTT)** and **Amazon SNS**, records audit history in a local **SQLite** database, and visualizes security status using a **Virtual LED indicator** (Green = Secure, Blinking Red = Security Risk) on a Dockerized web dashboard.

---

## 1. System Architecture

```
+---------------------------------------------------------------------------------------------------+
|                                  DOCKER ENVIRONMENT - LAPTOP                                      |
|                                                                                                   |
|  +-------------------------------------+         +---------------------------------------------+  |
|  |     Frontend Container (:8080)      |         |          Backend Container (:5000)          |  |
|  |           (Nginx Alpine)            |         |             (Python Flask + Boto3)          |  |
|  |                                     |         |                                             |  |
|  |  * Virtual LED (Green / Blinking Red| Reverse |  * REST API (/api/status, /api/scan)        |  |
|  |  * Manual Audit Scan Button         | Proxy   |  * SQLite DB (Scan History Persistence)     |  |
|  |  * Live Security Findings Display   | ------> |  * AWS IoT Core MQTT Listener (paho-mqtt)   |  |
|  |  * Audit History Log Table          |         |  * Local Simulation & Threat Injector       |  |
|  +-------------------------------------+         +----------------------+----------------------+  |
+-------------------------------------------------------------------------|-------------------------+
                                                                          |
                                  Manual Trigger (Boto3 / REST)           | MQTT Telemetry / TLS
                                  +---------------------------------------+
                                  |
                                  v
+---------------------------------------------------------------------------------------------------+
|                                          AWS CLOUD LAYER                                          |
|                                                                                                   |
|  +---------------------------+       +----------------------------+      +---------------------+  |
|  |    Amazon EventBridge     |       |         AWS Lambda         |      |    Amazon S3        |  |
|  |   (Scheduled Scan Cron)   | ----> |     (Security Scanner)     | ---> | (Monitored Buckets) |  |
|  +---------------------------+       +--------------+-------------+      +---------------------+  |
|                                                     |                                             |
|                                    +----------------+----------------+                            |
|                                    |                                 |                            |
|                                    v                                 v                            |
|                       +--------------------------+     +--------------------------+               |
|                       |       AWS IoT Core       |     |        Amazon SNS        |               |
|                       |  (MQTT: s3/security/..)  |     |  (Email Security Alert)  |               |
|                       +--------------------------+     +--------------------------+               |
+---------------------------------------------------------------------------------------------------+
```

---

## 2. Project Folder Structure

```
Cloud-Security-Alert-System/
│
├── frontend/
│   ├── index.html          # Responsive cybersecurity dashboard with Virtual LED
│   ├── style.css           # Industrial styling, dark theme, and glowing LED animations
│   ├── script.js           # Live polling (2s), manual scan trigger, and history renderer
│   ├── nginx.conf          # Nginx reverse proxy configuration for /api/ routing
│   └── Dockerfile          # Nginx Alpine container definition
│
├── backend/
│   ├── app.py              # Flask API server (/api/status, /api/scan, /api/history)
│   ├── aws_service.py      # Boto3 client invoking AWS Lambda (with local simulation fallback)
│   ├── mqtt_service.py     # Background MQTT subscriber listening to AWS IoT Core topic
│   ├── database.py         # SQLite data access layer managing audit history records
│   ├── requirements.txt    # Pinned Python package dependencies
│   └── Dockerfile          # Python 3.12-slim non-root container definition
│
├── lambda/
│   ├── security_scanner.py # Standalone Lambda function: checks S3, publishes to IoT & SNS
│   └── requirements.txt    # Lambda dependencies
│
├── aws/
│   ├── iam-policy.json     # Least-privilege IAM policy for Lambda execution role
│   └── iot-policy.json     # AWS IoT Core policy for MQTT device connection
│
├── docker-compose.yml      # Orchestrates Frontend (:8080) and Backend (:5000)
├── .env                    # Active local environment variables
├── .env.example            # Environment template documenting all configuration options
├── .gitignore              # Ignores sensitive certificates, virtual environments, and SQLite DB
└── README.md               # Complete project documentation and lab guide
```

---

## 3. Step-by-Step Implementation Guide (Phases 1–10)

### Phase 1: Project Setup & Docker Verification
Ensure Docker Desktop is running on your machine:
```powershell
docker --version
docker compose version
```
Clone or navigate to the project directory:
```powershell
cd C:\Users\Gatekeeper\.gemini\antigravity\scratch\Cloud-Security-Alert-System
```

---

### Phase 2: Frontend Dashboard (Nginx)
The frontend provides:
- A **Virtual Hardware LED** mimicking an ESP32 alert indicator:
  - **SECURE**: Steady emerald green glow with *"All Monitored Buckets Safe"*.
  - **SECURITY RISK**: Pulsing bright neon red beacon with *"Insecure S3 Bucket Detected!"*.
- **Manual Scan Trigger Button**: Initiates an on-demand audit.
- **Simulation Control Buttons**: Allows instant testing of public threat and secure states.
- **Scan History Table**: Chronological table populated from SQLite.

---

### Phase 3: Backend Development (Flask & SQLite)
The backend exposes:
- `GET /api/status`: Latest security status, active mode, and bucket findings.
- `POST /api/scan`: Triggers an on-demand audit via AWS Lambda or local simulation.
- `GET /api/history`: Returns historical audit records from SQLite.
- `POST /api/simulate-threat`: Injects a simulated public bucket finding for lab testing.
- `POST /api/simulate-secure`: Restores the secure green state.
- `GET /api/health`: Container health check endpoint.

---

### Phase 4: Docker Integration & Local Execution
Start both containers with a single Docker Compose command:
```powershell
docker compose up --build
```
*What happens:*
1. Docker builds the `backend` container (`python:3.12-slim`), initializes `backend/data/security_scans.db`, and binds port `5000`.
2. Docker builds the `frontend` container (`nginx:alpine`), copies static assets, configures proxy forwarding to `http://backend:5000/api/`, and binds port `8080`.
3. Open your browser at:
   ```
   http://localhost:8080
   ```
4. Click **"⚡ Trigger Manual Security Scan"** to perform an audit.
5. Click **"Simulate Public Risk"** to watch the Virtual LED ignite into a **blinking red alert**.
6. Click **"Simulate Secure State"** to return the Virtual LED to **green**.

To stop the containers:
```powershell
docker compose down
```

---

### Phase 5: AWS S3 & Lambda Deployment (AWS Cloud Layer)

When deploying to live AWS:

1. **Create IAM Role**:
   - Go to **AWS IAM** > **Roles** > **Create Role** (Trusted entity: **Lambda**).
   - Attach the inline policy defined in `aws/iam-policy.json`.
   - Name the role `S3SecurityScannerLambdaRole`.

2. **Create AWS Lambda Function**:
   - Go to **AWS Lambda** > **Create function**.
   - Function name: `s3-security-scanner`.
   - Runtime: **Python 3.12**.
   - Execution role: Use existing role `S3SecurityScannerLambdaRole`.
   - Paste the code from `lambda/security_scanner.py`.

3. **Configure Environment Variables in Lambda**:
   - `AWS_REGION`: e.g. `ap-south-1`
   - `SNS_TOPIC_ARN`: ARN of your alert SNS topic.
   - `IOT_TOPIC`: `s3/security/status`

---

### Phase 6: AWS IoT Core Configuration (MQTT)

1. **Create IoT Policy**:
   - In AWS IoT Core Console > **Security** > **Policies** > **Create**.
   - Name: `SecurityMonitorIoTPolicy`.
   - Paste contents of `aws/iot-policy.json`.

2. **Create IoT Thing & Certificates**:
   - In AWS IoT Core Console > **Manage** > **All devices** > **Things** > **Create thing**.
   - Name: `DockerBackendSecurityMonitor`.
   - Download the 3 certificate files into `backend/certs/`:
     - Device certificate (`certificate.pem.crt`)
     - Private key (`private.pem.key`)
     - Amazon Root CA 1 (`root-CA.crt`)
   - Attach `SecurityMonitorIoTPolicy` to the certificate.

3. **Obtain IoT Endpoint**:
   - Go to **IoT Core** > **Settings** > copy the **Endpoint** (e.g. `a3xxxxxxxxxxxx-ats.iot.ap-south-1.amazonaws.com`).
   - Update `AWS_IOT_ENDPOINT` in `.env`.

---

### Phase 7: Amazon SNS Configuration (Email Alerts)

1. **Create SNS Topic**:
   - In AWS SNS Console > **Topics** > **Create topic**.
   - Type: **Standard**, Name: `s3-security-alerts`.
   - Copy the Topic ARN into `.env` and Lambda environment variables.

2. **Subscribe Email**:
   - Create subscription > Protocol: **Email**, Endpoint: `your-email@example.com`.
   - Check your inbox and click **Confirm subscription**.

---

### Phase 8: Amazon EventBridge (Scheduled Automatic Scans)

1. Navigate to **Amazon EventBridge** > **Rules** > **Create rule**.
2. Rule name: `s3-security-scheduled-scan`.
3. Rule type: **Schedule** > e.g., Rate expression: `rate(10 minutes)`.
4. Target: **Lambda function** > select `s3-security-scanner`.
5. Configure target input:
   ```json
   {"trigger": "SCHEDULED_EVENTBRIDGE"}
   ```
6. Every 10 minutes, EventBridge invokes Lambda, which scans S3, dispatches status to AWS IoT Core, and pushes updates live to your Docker backend!

---

### Phase 9: Testing & Integration

#### Scenario 1: Bucket is Secure
1. All buckets have S3 Block Public Access enabled.
2. Lambda audit determines `status = "SECURE"`.
3. Message published to IoT Core topic `s3/security/status`.
4. Docker backend receives MQTT message and saves to SQLite.
5. Dashboard displays **Green Virtual LED** (SECURE).

#### Scenario 2: Public-Access Risk Detected
1. A bucket has Public Access Block disabled and ACL `public-read` applied.
2. Lambda audit detects public exposure: `status = "SECURITY_RISK"`.
3. Finding published to IoT Core topic `s3/security/status`.
4. SNS sends immediate email notification with exposure reasons.
5. Docker backend records security finding into SQLite.
6. Dashboard displays **Blinking Red Virtual LED** (SECURITY ALERT).

---

### Phase 10: Documentation & Submission

| Deliverable Component | Verification Detail |
|---|---|
| **Frontend Container** | Running on port `8080`, accessible via `http://localhost:8080`. |
| **Backend Container** | Running on port `5000`, exposes `/api/status`, `/api/scan`, `/api/history`. |
| **Virtual Hardware LED** | Green when secure; glowing blinking red when risk detected. |
| **SQLite Persistence** | Audit records saved in `backend/data/security_scans.db`. |
| **AWS Lambda Scanner** | Standalone code in `lambda/security_scanner.py`. |
| **AWS IoT MQTT Integration** | Background subscriber in `backend/mqtt_service.py`. |
| **Amazon SNS Alerts** | Dispatches security emails upon public bucket detection. |
| **Docker Compose** | Single command deployment: `docker compose up --build`. |

---

## 4. Troubleshooting Guide

| Issue | Cause | Solution |
|---|---|---|
| `docker: command not found` | Docker Desktop is not installed or not running. | Launch **Docker Desktop** on Windows. Restart PowerShell. |
| Virtual LED stays grey / "Backend: Offline" | Backend container failed to boot or port 5000 blocked. | Check container logs: `docker logs security-alert-backend`. Ensure port 5000 is free. |
| `paho.mqtt` connection errors | Missing certificate files in `backend/certs/` or incorrect endpoint. | If testing purely on laptop without AWS IoT Core, leave `SIMULATION_MODE=true` in `.env`. |
| SQLite database permission error | File ownership issue in container. | The Dockerfile automatically assigns permissions to `appuser` (UID 1000). |
| SNS Email not arriving | Subscription pending confirmation. | Check your email inbox / spam folder and click the AWS confirmation link. |
