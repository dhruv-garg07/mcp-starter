# api/mcp.py

import os
import re
from datetime import datetime, timezone, timedelta
from typing import Any, Optional
import json
import base64
import asyncio

# --- Import required libraries ---
from fastapi import Request
from fastmcp import FastMCP
from mcp.server.auth.provider import AccessToken
from fastmcp.server.auth.providers.bearer import BearerAuthProvider, RSAKeyPair

# --- Firestore Imports ---
# These are the only external dependencies needed for the core functionality
from google.cloud import firestore
import google.auth.credentials

# --- Environment Variables ---
TOKEN = os.environ.get("AUTH_TOKEN")
MY_NUMBER = os.environ.get("MY_NUMBER")
FIRESTORE_CREDS_B64 = os.environ.get("FIRESTORE_CREDS_B64")

if not all([TOKEN, MY_NUMBER, FIRESTORE_CREDS_B64]):
    raise RuntimeError("AUTH_TOKEN, MY_NUMBER, and FIRESTORE_CREDS_B64 must be set.")

# --- Auth Provider (matches starter code format) ---
class SimpleBearerAuthProvider(BearerAuthProvider):
    def __init__(self, token: str):
        k = RSAKeyPair.generate()
        super().__init__(public_key=k.public_key, jwks_uri=None, issuer=None, audience=None)
        self.token = token

    async def load_access_token(self, token: str) -> AccessToken | None:
        if token == self.token:
            return AccessToken(token=token, client_id="puch-client", scopes=["*"], expires_at=None)
        return None

# --- MCP Server Setup (matches starter code format) ---
mcp = FastMCP(
    "Workout Logger",
    auth=SimpleBearerAuthProvider(TOKEN),
)

# --- OPTIMIZATION: Lazy-Loaded Firestore Client ---
db = None
def get_db_client():
    global db
    if db is None:
        try:
            creds_json_str = base64.b64decode(FIRESTORE_CREDS_B64).decode('utf-8')
            creds_info = json.loads(creds_json_str)
            credentials = google.oauth2.service_account.Credentials.from_service_account_info(creds_info)
            db = firestore.Client(credentials=credentials)
            print("Firestore client initialized on first request.")
        except Exception as e:
            print(f"CRITICAL: Failed to initialize Firestore client: {e}")
    return db

# --- Helper Function to Parse Workout String ---
def parse_workout_string(log_string: str) -> dict | None:
    pattern = re.compile(
        r"^(?P<name>[\w\s]+?)\s+"
        r"(?P<weight>[\d\.]+)"
        r"(?:\s*x\s*(?P<per_side>2))?"
        r"\s*x\s*(?P<sets>[\d]+)"
        r"\s*x\s*(?P<reps>[\d]+)$",
        re.IGNORECASE
    )
    match = pattern.match(log_string.strip())
    if not match:
        simple_pattern = re.compile(
            r"^(?P<name>[\w\s]+?)\s+"
            r"(?P<weight>[\d\.]+)"
            r"\s*x\s*(?P<reps>[\d]+)$",
            re.IGNORECASE
        )
        match = simple_pattern.match(log_string.strip())
        if not match:
            return None
    data = match.groupdict()
    return {
        "name": data["name"].strip().title(),
        "weight": float(data["weight"]),
        "sets": int(data.get("sets") or 1),
        "reps": int(data["reps"]),
        "per_side": data.get("per_side") is not None
    }


# --- Tool: validate ---
@mcp.tool(description="Validates the server connection.")
async def validate() -> str:
    return MY_NUMBER


# --- Tool: greet ---
@mcp.tool(description=json.dumps({
    "description": "Greets the user and lists available commands.",
    "use_when": "When the user sends a greeting like 'hi', 'hello', or asks for 'help'."
}))
async def greet(request: Request):
    body = await request.json()
    user_name = body.get("message", {}).get("user", {}).get("name", "there")
    
    welcome_message = (
        f"Hi {user_name}! I'm your personal workout logger.\n\n"
        "Here's what you can do:\n\n"
        "1️⃣ **Log a workout:**\n"
        "   - `log Bench Press 60x5x5`\n"
        "   - `add Squat 100x3x8`\n\n"
        "2️⃣ **View your progress:**\n"
        "   - `show my progress for Bench Press`\n"
        "   - `view history for Squat`"
    )
    return [{"type": "text", "text": welcome_message}]


# --- Tool: log_workout ---
@mcp.tool(description=json.dumps({
    "description": "Logs a workout entry into the user's personal database.",
    "use_when": "When the user says 'log', 'add', or 'save' a workout. Example format: 'Squat 100x5x5' or 'Incline Curl 12.5x2x8'."
}))
async def log_workout(request: Request, entry: str):
    db_client = get_db_client()
    if not db_client:
        return [{"type": "text", "text": "Error: Database is not configured correctly."}]

    parsed_data = parse_workout_string(entry)
    if not parsed_data:
        return [{"type": "text", "text": f"Sorry, I couldn't understand that format. Try something like 'Bench Press 60x5x5'."}]

    body = await request.json()
    user_id = body.get("message", {}).get("user", {}).get("id")
    if not user_id:
        return [{"type": "text", "text": "Error: Could not identify user."}]

    parsed_data["user_id"] = user_id
    parsed_data["timestamp"] = datetime.now(timezone.utc)

    try:
        db_client.collection("workouts").add(parsed_data)
        log_msg = (
            f"💪 Logged: {parsed_data['name']}!\n"
            f"- Weight: {parsed_data['weight']} kg"
            f"{' (per side)' if parsed_data['per_side'] else ''}\n"
            f"- Sets: {parsed_data['sets']}\n"
            f"- Reps: {parsed_data['reps']}"
        )
        return [{"type": "text", "text": log_msg}]
    except Exception as e:
        return [{"type": "text", "text": f"Sorry, there was an error saving your workout: {e}"}]


# --- Tool: view_progress (Simplified: No Graph) ---
@mcp.tool(description=json.dumps({
    "description": "Shows a user's personal, saved workout history for a specific exercise from the database.",
    "use_when": "When the user asks to 'see', 'view', 'show', or 'check' their logs, history, or progress for an exercise."
}))
async def view_progress(request: Request, exercise: str):
    db_client = get_db_client()
    if not db_client:
        return [{"type": "text", "text": "Error: Database is not configured correctly."}]

    body = await request.json()
    user_id = body.get("message", {}).get("user", {}).get("id")
    if not user_id:
        return [{"type": "text", "text": "Error: Could not identify user."}]

    exercise_name = exercise.strip().title()

    try:
        # Query Firestore for the last 5 entries for this user and exercise
        docs = db_client.collection("workouts") \
            .where("user_id", "==", user_id) \
            .where("name", "==", exercise_name) \
            .order_by("timestamp", direction=firestore.Query.DESCENDING) \
            .limit(5) \
            .stream()
        
        logs = list(docs)
        if not logs:
            return [{"type": "text", "text": f"No logs found for '{exercise_name}'. Try logging one first!"}]

        summary_text = f"📈 Last 5 logs for {exercise_name}:\n\n"
        ist = timezone(timedelta(hours=5, minutes=30))

        for log in logs:
            data = log.to_dict()
            timestamp_ist = data['timestamp'].astimezone(ist)
            date_str = timestamp_ist.strftime("%b %d, %Y")
            log_str = (f"- *{date_str}*: {data['weight']}kg x {data['sets']}s x {data['reps']}r")
            summary_text += log_str + "\n"
        
        return [{"type": "text", "text": summary_text}]

    except Exception as e:
        return [{"type": "text", "text": f"Sorry, there was an error fetching your progress: {e}"}]


# --- CRITICAL FIX FOR HOSTING (Vercel, Render, etc.) ---
# This line exposes the underlying FastAPI application that FastMCP builds.
# Hosting services look for a variable named 'app' to run.
app = mcp.app

# --- Run MCP Server Locally ---
async def main():
    print("🚀 Starting MCP server on http://0.0.0.0:8086")
    await mcp.run_async("streamable-http", host="0.0.0.0", port=8086)

if __name__ == "__main__":
    asyncio.run(main())
