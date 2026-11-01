import hashlib, hmac, json, logging, os, re, time
from collections import Counter, deque
from threading import Lock
from fastapi import FastAPI, Header, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

try:
    from google.cloud import firestore
except ImportError:
    firestore = None

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("mitm-cloud-guard")
APP_NAME = "MITM Cloud Guard"
CLIENT_ID = os.getenv("DEMO_CLIENT_ID", "demo-client")
CLIENT_SECRET = os.getenv("DEMO_CLIENT_SECRET", "")
print(
    "SERVER SECRET FINGERPRINT:",
    hashlib.sha256(CLIENT_SECRET.encode()).hexdigest()[:12]
)
MAX_CLOCK_SKEW_SECONDS = int(os.getenv("MAX_CLOCK_SKEW_SECONDS", "300"))
USE_FIRESTORE = os.getenv("USE_FIRESTORE", "false").lower() == "true"

if not CLIENT_SECRET or len(CLIENT_SECRET) < 32:
    raise RuntimeError("Set DEMO_CLIENT_SECRET to a random secret of at least 32 characters.")

app = FastAPI(title=APP_NAME, version="1.1.0")
app.mount("/static", StaticFiles(directory="static"), name="static")
_memory_nonces = {}
_memory_lock = Lock()
_recent_events = deque(maxlen=100)
_counts = Counter()
_db = None

if USE_FIRESTORE:
    if firestore is None:
        raise RuntimeError("Install google-cloud-firestore to use Firestore.")
    _db = firestore.Client()

def log_event(event_type, status, detail, client_id=None):
    event = {"time": int(time.time()), "type": event_type, "status": status,
             "detail": detail, "client_id": client_id or "unknown"}
    _recent_events.appendleft(event)
    _counts[status] += 1
    logger.info(json.dumps({"security_event": event}))

def claim_nonce(client_id, nonce, timestamp):
    key = hashlib.sha256(f"{client_id}:{nonce}".encode()).hexdigest()
    expiry = timestamp + MAX_CLOCK_SKEW_SECONDS
    if _db is not None:
        ref = _db.collection("used_nonces").document(key)
        @firestore.transactional
        def create_once(transaction):
            snap = ref.get(transaction=transaction)
            if snap.exists:
                return False
            transaction.create(ref, {"client_id": client_id, "created_at": firestore.SERVER_TIMESTAMP,
                                     "expires_at_epoch": expiry})
            return True
        return create_once(_db.transaction())
    # FREE demo mode: one Cloud Run instance, in-memory nonce cache.
    # Nonces are not shared or durable across instance restarts.
    now = int(time.time())
    with _memory_lock:
        for old in [k for k, v in _memory_nonces.items() if v < now]:
            _memory_nonces.pop(old, None)
        if key in _memory_nonces:
            return False
        _memory_nonces[key] = expiry
        return True

def sign_message(timestamp, nonce, body):
    msg = timestamp.encode() + b"." + nonce.encode() + b"." + body
    return hmac.new(CLIENT_SECRET.encode(), msg, hashlib.sha256).hexdigest()

@app.get("/")
async def dashboard():
    return FileResponse("static/index.html")

@app.get("/health")
async def health():
    return {"status": "ok", "service": APP_NAME}

@app.get("/api/status")
async def status():
    return {"service": APP_NAME,
            "replay_store": "Firestore" if _db is not None else "in-memory (free demo mode)",
            "counts": dict(_counts), "recent_events": list(_recent_events)}

@app.post("/api/secure")
async def secure_endpoint(request: Request,
    x_client_id: str = Header(default=""), x_timestamp: str = Header(default=""),
    x_nonce: str = Header(default=""), x_signature: str = Header(default="")):
    body = await request.body()
    if x_client_id != CLIENT_ID:
        log_event("authentication", "blocked", "Unknown client ID", x_client_id)
        return JSONResponse({"result":"blocked","reason":"unknown_client"}, status_code=401)
    if not re.fullmatch(r"\d{10}", x_timestamp or ""):
        log_event("validation","blocked","Missing or malformed timestamp",x_client_id)
        return JSONResponse({"result":"blocked","reason":"invalid_timestamp"},status_code=400)
    if not re.fullmatch(r"[A-Za-z0-9_-]{16,80}", x_nonce or ""):
        log_event("validation","blocked","Missing or malformed nonce",x_client_id)
        return JSONResponse({"result":"blocked","reason":"invalid_nonce"},status_code=400)
    ts = int(x_timestamp)
    if abs(int(time.time()) - ts) > MAX_CLOCK_SKEW_SECONDS:
        log_event("freshness","blocked","Timestamp outside allowed window",x_client_id)
        return JSONResponse({"result":"blocked","reason":"stale_or_future_request"},status_code=401)
    expected = sign_message(x_timestamp, x_nonce, body)
    if not hmac.compare_digest(expected, x_signature or ""):
        log_event("integrity","blocked","HMAC signature mismatch; payload may have changed",x_client_id)
        return JSONResponse({"result":"blocked","reason":"signature_mismatch"},status_code=401)
    try:
        if not claim_nonce(x_client_id, x_nonce, ts):
            log_event("replay","blocked","Nonce has already been used",x_client_id)
            return JSONResponse({"result":"blocked","reason":"replay_detected"},status_code=409)
    except Exception:
        logger.exception("Replay-protection store error")
        log_event("storage","error","Replay-protection store unavailable",x_client_id)
        return JSONResponse({"result":"error","reason":"replay_store_unavailable"},status_code=503)
    try:
        payload = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        log_event("payload","blocked","Body must be valid JSON",x_client_id)
        return JSONResponse({"result":"blocked","reason":"invalid_json"},status_code=400)
    log_event("request","accepted","Valid signature, fresh timestamp and unused nonce",x_client_id)
    return {"result":"accepted","message":"Request passed integrity and replay checks","received":payload}
