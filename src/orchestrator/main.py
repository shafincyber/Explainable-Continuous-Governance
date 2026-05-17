from fastapi import FastAPI, BackgroundTasks, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
from kafka import KafkaProducer
import json
import requests
import os

app = FastAPI(title="Sentinel-V2 Orchestrator", version="2.0.0")

# --- KAFKA PRODUCER ---
try:
    producer = KafkaProducer(
        bootstrap_servers=['localhost:9092'],
        value_serializer=lambda v: json.dumps(v).encode('utf-8')
    )
    print("[+] Kafka Producer connected successfully.")
except Exception as e:
    print(f"[-] Kafka Connection Error: {e}")
    producer = None

# --- WEBSOCKET MANAGER ---
class ConnectionManager:
    def __init__(self):
        self.active_connections: list[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast(self, message: dict):
        for connection in self.active_connections:
            try:
                await connection.send_json(message)
            except Exception:
                pass

manager = ConnectionManager()


# --- CHATOPS MANAGER ---
DISCORD_WEBHOOK_URL = os.getenv("CHATOPS_WEBHOOK", "")

def send_chatops_alert(trigger_id: str, regulations: str, status: str):
    if not DISCORD_WEBHOOK_URL: return
    color = 65280 if status == "REMEDIATED" else 16711680
    payload = {
        "embeds": [{
            "title": f"🛡️ SENTINEL GRC ALERT: {status}",
            "description": f"**Trigger:** `{trigger_id}`\n**Mandate:** {regulations}",
            "color": color,
            "footer": {"text": "Sentinel-V2 Autonomous Engine"}
        }]
    }
    try: requests.post(DISCORD_WEBHOOK_URL, json=payload, timeout=2)
    except: pass

class AlertMessage(BaseModel):
    trigger_id: str
    regulations: str
    status: str

# --- MODELS ---
class ScanRequest(BaseModel):
    repository_url: str
    commit_hash: str
    branch: str = "main"

class LogMessage(BaseModel):
    source: str 
    message: str

# --- ENDPOINTS ---
@app.post("/api/v2/alert")
async def trigger_alert(alert: AlertMessage, background_tasks: BackgroundTasks):
    background_tasks.add_task(send_chatops_alert, alert.trigger_id, alert.regulations, alert.status)
    return {"status": "alert_queued"}

@app.get("/")
async def serve_dashboard():
    dashboard_path = os.path.join(os.path.dirname(__file__), "..", "ui", "dashboard.html")
    if os.path.exists(dashboard_path):
        with open(dashboard_path, "r", encoding="utf-8") as f:
            return HTMLResponse(content=f.read(), status_code=200)
    return {"message": "Sentinel-V2 API Online. Dashboard UI not found."}

@app.websocket("/ws/logs")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)

@app.post("/api/v2/log_sink")
async def receive_log(log: LogMessage):
    await manager.broadcast({"source": log.source, "message": log.message})
    return {"status": "broadcasted"}

@app.post("/api/v2/scan")
async def trigger_scan(payload: ScanRequest):
    if not producer:
        raise HTTPException(status_code=500, detail="Kafka broker is down.")

    event_data = {
        "repository_url": payload.repository_url,
        "commit_hash": payload.commit_hash,
        "branch": payload.branch,
        "status": "QUEUED"
    }

    producer.send('sentinel-scans', event_data)
    producer.flush() 
    await manager.broadcast({"source": "audit", "message": f"[*] Webhook received: {payload.repository_url}. Event queued."})
    
    return {"status": "Scan Queued", "event": event_data}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)