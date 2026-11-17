New dashboard UI - replaces: index.html, style.css, script.js
Keep your existing: Dockerfile, nginx.conf, and the whole backend (no backend changes needed).

Deploy (on the EC2 instance, in ~/Cloud-Security-Alert-System):
  1. Copy the 3 files into the frontend/ folder (overwrite the old ones).
  2. docker-compose up -d --build frontend
  3. Hard-refresh the browser (Ctrl+F5).
