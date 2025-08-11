# api/mcp.py

import os
import re
from datetime import datetime, timezone, timedelta
from typing import Any, Optional

# --- Import required libraries ---
from fastapi import Request
from pydantic import BaseModel
from fastmcp import FastMCP
from mcp.server.auth.provider import AccessToken
from fastmcp.server.auth.providers.bearer import BearerAuthProvider, RSAKeyPair

# --- Firestore Imports ---
from google.cloud import firestore
import google.auth.credentials
import json
import base64

# --- Environment Variables ---
TOKEN = os.environ.get("AUTH_TOKEN")
MY_NUMBER = os.environ.get("MY_NUMBER")
FIRESTORE_CREDS_B64 = os.environ.get("FIRESTORE_CREDS_B64")

if not all([TOKEN, MY_NUMBER, FIRESTORE_CREDS_B64]):
    raise RuntimeError("AUTH_TOKEN, MY_NUMBER, and FIRESTORE_CREDS_B64 must be set.")

# --- Auth Provider (for FastMCP) ---
class SimpleBearerAuthProvider(BearerAuthProvider):
    def __init__(self, token: str):
        k = RSAKeyPair.generate()
        super().__init__(public_key=k.public_key, jwks_uri=None, issuer=None, audience=None)
        self.token = token

    async def load_access_token(self, token: str) -> AccessToken | None:
        if token == self.token:
            return AccessToken(token=token, client_id="puch-client", scopes=["*"], expires_at=None)
        return None

# --- Rich Tool Description Model ---
class RichToolDescription(BaseModel):
    description: str
    use_when: str

# --- MCP Server Setup ---
# We use FastMCP to build our server and its manifest automatically.
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
greet_desc = RichToolDescription(
    description="Greets the user and lists available commands.",
    use_when="When the user sends a greeting like 'hi', 'hello', or asks for 'help'."
)
@mcp.tool(description=greet_desc.model_dump_json())
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
log_workout_desc = RichToolDescription(
    description="Logs a workout entry into the user's personal database.",
    use_when="When the user says 'log', 'add', or 'save' a workout. Example format: 'Squat 100x5x5' or 'Incline Curl 12.5x2x8'."
)
@mcp.tool(description=log_workout_desc.model_dump_json())
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


# --- Tool: view_progress ---
view_progress_desc = RichToolDescription(
    description="Shows a user's personal, saved workout history and a progress graph for a specific exercise from the database.",
    use_when="When the user asks to 'see', 'view', 'show', or 'check' their logs, history, or progress for an exercise."
)
@mcp.tool(description=view_progress_desc.model_dump_json())
async def view_progress(request: Request, exercise: str):
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    import io

    db_client = get_db_client()
    if not db_client:
        return [{"type": "text", "text": "Error: Database is not configured correctly."}]

    body = await request.json()
    user_id = body.get("message", {}).get("user", {}).get("id")
    if not user_id:
        return [{"type": "text", "text": "Error: Could not identify user."}]

    exercise_name = exercise.strip().title()

    try:
        docs = db_client.collection("workouts") \
            .where("user_id", "==", user_id) \
            .where("name", "==", exercise_name) \
            .order_by("timestamp", direction=firestore.Query.ASCENDING) \
            .limit(20) \
            .stream()
        
        logs = list(docs)
        if not logs:
            return [{"type": "text", "text": f"No logs found for '{exercise_name}'. Try logging one first!"}]

        summary_text = f"📈 Progress for {exercise_name}:\n\n"
        ist = timezone(timedelta(hours=5, minutes=30))

        for log in logs[-5:]:
            data = log.to_dict()
            timestamp_ist = data['timestamp'].astimezone(ist)
            date_str = timestamp_ist.strftime("%b %d")
            log_str = (f"- *{date_str}*: {data['weight']}kg x {data['sets']}s x {data['reps']}r")
            summary_text += log_str + "\n"

        dates = [log.to_dict()['timestamp'].astimezone(ist).strftime("%d-%b") for log in logs]
        weights = [log.to_dict()['weight'] for log in logs]
        
        fig, ax = plt.subplots(figsize=(10, 6))
        ax.plot(dates, weights, marker='o', linestyle='-', color='b')
        ax.set_title(f"Weight Progression for {exercise_name}", fontsize=16)
        ax.set_xlabel("Date", fontsize=12)
        ax.set_ylabel("Weight (kg)", fontsize=12)
        ax.grid(True, which='both', linestyle='--', linewidth=0.5)
        plt.xticks(rotation=45, ha="right")
        plt.tight_layout()

        buf = io.BytesIO()
        plt.savefig(buf, format='png')
        buf.seek(0)
        image_base64 = base64.b64encode(buf.read()).decode('utf-8')
        buf.close()
        plt.close(fig)

        return [
            {"type": "text", "text": summary_text},
            {"type": "image", "mimeType": "image/png", "data": image_base64}
        ]
    except Exception as e:
        return [{"type": "text", "text": f"Sorry, there was an error fetching your progress: {e}"}]


# --- CRITICAL FIX FOR VERCEL ---
# Expose the underlying FastAPI app for Vercel to run.
app = mcp.app
