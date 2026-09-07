#!/usr/bin/env bash
cd /opt/audit-api
source venv/bin/activate
uvicorn app.main:app --host 127.0.0.1 --port 8000
