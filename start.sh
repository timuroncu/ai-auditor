#!/bin/bash

# AI Security Auditor - Startup Script
# Starts both the Flask API backend and React UI frontend

echo "=========================================="
echo "   AI Security Auditor - Starting..."
echo "=========================================="

# Add Python bin to PATH
export PATH="$PATH:/Users/keremyunusoglu/Library/Python/3.9/bin"

# Kill any existing processes on our ports
echo "Cleaning up existing processes..."
lsof -ti:5001 | xargs kill -9 2>/dev/null
lsof -ti:3000 | xargs kill -9 2>/dev/null

# Start Flask API in background
echo "Starting Flask API on port 5001..."
cd "$(dirname "$0")"
python3 api.py &
API_PID=$!

# Wait for API to start
sleep 2

# Start React UI
echo "Starting React UI on port 3000..."
cd ui
npm start &
UI_PID=$!

echo ""
echo "=========================================="
echo "   Services Started!"
echo "=========================================="
echo "   API:  http://localhost:5001"
echo "   UI:   http://localhost:3000"
echo "=========================================="
echo ""
echo "Press Ctrl+C to stop all services"

# Wait for Ctrl+C
trap "kill $API_PID $UI_PID 2>/dev/null; exit" SIGINT SIGTERM

wait
