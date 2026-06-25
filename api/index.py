"""Vercel entry point for AgentGuard."""
import sys
import os

# Add backend/ to path so we can import web.py
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))

from web import app

# Vercel expects an 'app' object at module level
# The FastAPI app is already initialized in web.py
