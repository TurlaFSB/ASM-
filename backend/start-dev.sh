#!/bin/bash
Xvfb :99 -screen 0 1280x1024x24 &
exec python -m uvicorn backend.main:app --host 0.0.0.0 --port 8000 --reload
