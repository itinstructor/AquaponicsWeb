#!/usr/bin/env python3
"""
Flask web application that shows two live MJPEG camera streams:
 - Fish Tank (camera 0)
 - Plant Bed (camera 2 mapped as /stream1.mjpg on the Pi side)

Designed with clear comments for learners.
This version keeps:
 - Clean structure
 - Rotating log files (no noisy debug routes)
 - Simple relay caching for efficiency
 - Cloudflare Turnstile protection (via turnstile.py module)

Does NOT include extra debug endpoints or complex UI logic.
"""

from datetime import datetime
import os
from logging_config import setup_logging, get_logger

setup_logging("main_app.log")  # MUST be first

# Now import Flask and the rest
from flask import Flask, render_template, request, url_for, Response, redirect, session, jsonify
import threading
import time
from dotenv import load_dotenv

# Load environment variables
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
load_dotenv(os.path.join(BASE_DIR, ".env"))

logger = get_logger(__name__)
logger.info("Application starting...")

# TEST: Logging works at startup
logger = get_logger("test_logger")
logger.info("TEST: Logging works at startup")

# Local modules that handle pulling frames from upstream cameras
from cached_relay import CachedMediaRelay

# ---------------------------------------------------------------------------
# STREAM RELAY STATE / CONFIG
# ---------------------------------------------------------------------------
WARMUP_TIMEOUT = 5.0          # seconds to wait for first frame
QUEUE_TIMEOUT = 2.0           # seconds waiting for a frame from client queue
MAX_CONSECUTIVE_TIMEOUTS = 10 # drop client after this many timeouts

_media_relays = {}
_media_lock = threading.Lock()

def get_media_relay(url):
    with _media_lock:
        relay = _media_relays.get(url)
        if relay is None:
            relay = CachedMediaRelay(url)
            _media_relays[url] = relay
            relay.start()
        return relay

# Database and visitor tracking
from database import db
from geomap_module import geomap_bp
from geomap_module.models import VisitorLocation
from geomap_module.helpers import get_ip, get_location
from geomap_module.routes import VISITOR_COOLDOWN_HOURS

# Turnstile bot protection
from turnstile import init_turnstile

from fish_cam_config import (
    DEFAULT_STREAM_HOST as CAM_HOST,
    DEFAULT_STREAM_PORT as CAM_PORT,
    DEFAULT_STREAM_PATH_0,
    DEFAULT_STREAM_PATH_1,
)

# Apply environment overrides if present
ENV_HOST = os.getenv("CAMERA_HOST")
ENV_PORT = os.getenv("CAMERA_PORT")

DEFAULT_STREAM_HOST = ENV_HOST.strip() if ENV_HOST else CAM_HOST
try:
    DEFAULT_STREAM_PORT = int(ENV_PORT) if ENV_PORT else CAM_PORT
except ValueError:
    logger.warning(f"Invalid CAMERA_PORT '{ENV_PORT}', using {CAM_PORT}")
    DEFAULT_STREAM_PORT = CAM_PORT

# Paths
DEFAULT_STREAM_PATH_0 = DEFAULT_STREAM_PATH_0
DEFAULT_STREAM_PATH_1 = DEFAULT_STREAM_PATH_1

# ---------------------------------------------------------------------------
# FLASK APP SETUP
# ---------------------------------------------------------------------------
app = Flask(
    __name__,
    static_folder='static',
    static_url_path='/aquaponics/static'
)
app.config['APPLICATION_ROOT'] = '/aquaponics'

# Secret key (load or generate)
SECRET_FILE = os.path.join(BASE_DIR, 'secret.key')
if os.path.exists(SECRET_FILE):
    with open(SECRET_FILE, 'rb') as f:
        app.secret_key = f.read().strip()
else:
    app.secret_key = os.urandom(32)
    try:
        with open(SECRET_FILE, 'wb') as f:
            f.write(app.secret_key)
    except Exception:
        logger.warning("Could not persist generated secret key")

# Database configuration (adjust if you use a different URI)
INSTANCE_DIR = r"c:/inetpub/aquaponics/instance"
os.makedirs(INSTANCE_DIR, exist_ok=True)

# Set both databases to be in the instance folder
FISH_BLOG_DB_PATH = os.path.join(app.instance_path, "fish_blog.db")
VISITORS_DB_PATH = os.path.join(app.instance_path, "visitors.db")

app.config["SQLALCHEMY_DATABASE_URI"] = (
    f"sqlite:///{FISH_BLOG_DB_PATH}"  # main DB
)
app.config["SQLALCHEMY_BINDS"] = {"visitors": f"sqlite:///{VISITORS_DB_PATH}"}
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

with app.app_context():
    db.init_app(app)
    try:
        db.create_all()
        db_path = app.config["SQLALCHEMY_DATABASE_URI"].replace("sqlite:///", "", 1)
        logger.info(f"Visitors DB ready: {db_path} exists={os.path.exists(db_path)}")
    except Exception as e:
        logger.exception(f"DB init failed: {e}")

try:
    app.register_blueprint(geomap_bp, url_prefix='/aquaponics/geomap')
except Exception as e:
    logger.exception(f"Failed registering geomap blueprint: {e}")

# Register the blog blueprint
logger.info("Attempting to import Aquaponics Blog blueprint...")
try:
    from blog import blog_bp  # Import here, just before registration

    logger.info(f"Blog blueprint imported: {blog_bp}")
    app.register_blueprint(blog_bp, url_prefix="/aquaponics")
    logger.info("Blog blueprint registered at /aquaponics")
except Exception as e:
    logger.exception("Failed to register Aquaponics Blog blueprint")
    logger.error(f"Error details: {str(e)}")

# Import BlogPost model for the index page query
try:
    from blog.models import BlogPost
    logger.info("Successfully imported BlogPost model for index page.")
except ImportError:
    BlogPost = None # Set to None if import fails, so app doesn't crash

# Create database tables if they don't exist
with app.app_context():
    try:
        db.create_all()
        logger.info("Database tables created/verified")
    except Exception as e:
        logger.exception("Failed to create database tables")

# Global error handlers for visibility
@app.errorhandler(500)
def handle_500(err):
    logger.exception(f"Unhandled 500 error: {err}")
    return render_template("error.html", message="Internal server error"), 500

@app.errorhandler(404)
def handle_404(err):
    return render_template("error.html", message="Not Found"), 404

# ---------------------------------------------------------------------------
# CONTENT SECURITY POLICY FOR THINGSPEAK IFRAMES
# ---------------------------------------------------------------------------
THINGSPEAK_READ_KEY = os.getenv("THINGSPEAK_READ_KEY")  # optional for private channel

@app.after_request
def allow_thingspeak(response):
    path = request.path.rstrip('/')
    if path == '/aquaponics/sensors':
        response.headers['Content-Security-Policy'] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://thingspeak.com https://thingspeak.mathworks.com https://cdn.jsdelivr.net; "
            "script-src-elem 'self' 'unsafe-inline' 'unsafe-eval' https://thingspeak.com https://thingspeak.mathworks.com https://cdn.jsdelivr.net; "
            "style-src 'self' 'unsafe-inline' https://thingspeak.com https://thingspeak.mathworks.com https://cdn.jsdelivr.net; "
            "style-src-elem 'self' 'unsafe-inline' https://thingspeak.com https://thingspeak.mathworks.com https://cdn.jsdelivr.net; "
            "img-src 'self' data: https://thingspeak.com https://thingspeak.mathworks.com; "
            "frame-src https://thingspeak.com https://thingspeak.mathworks.com; "
            "connect-src 'self' https://thingspeak.com https://thingspeak.mathworks.com https://api.thingspeak.com https://cdn.jsdelivr.net; "
            "font-src 'self' data: https://cdn.jsdelivr.net;"
        )
        response.headers.pop('X-Frame-Options', None)
    return response

@app.route("/aquaponics/sensors")
def sensors():
    return render_template("sensors.html", ts_read_key=THINGSPEAK_READ_KEY)

@app.route("/aquaponics/champions")
def champions():
    """Page recognizing Aquaponics Champions."""
    return render_template("champions.html")

@app.route("/aquaponics/about")
def about():
    """Static About page."""
    return render_template("about.html")

@app.route("/aquaponics/contact")
def contact():
    """Static Contact page."""
    return render_template("contact.html")

@app.route("/aquaponics/photos")
def photos():
    """Photo gallery page."""
    return render_template("photos.html")

@app.route("/aquaponics/stats")
def stats_page():
    """HTML page that displays waitress/server streaming statistics."""
    return render_template("waitress_stats.html")

# ---------------------------------------------------------------------------
# STREAM PROXY ENDPOINT
# ---------------------------------------------------------------------------
@app.route("/aquaponics/relay_status")
def relay_status():
    """Inspect current relay state (diagnostic)."""
    data = {}
    with _media_lock:
        for url, relay in _media_relays.items():
            with relay.lock:
                data[url] = {
                    "clients": len(relay.clients),
                    "running": relay.running,
                    "has_frame": relay.last_frame is not None,
                }
    return jsonify(data)

@app.route("/aquaponics/stream_proxy")
def stream_proxy():
    path = request.args.get("path", DEFAULT_STREAM_PATH_0)
    host = DEFAULT_STREAM_HOST
    port = DEFAULT_STREAM_PORT
    stream_url = f"http://{host}:{port}{path}"
    logger.info(f"Proxy upstream={stream_url}")
    relay = get_media_relay(stream_url)
    client_queue = relay.add_client()
    logger.info(f"Added client to relay {stream_url}; total_clients={len(relay.clients)}")

    def generate():
        waited = 0.0
        # Wait for first frame
        while relay.last_frame is None and waited < WARMUP_TIMEOUT and relay.running:
            time.sleep(0.25)
            waited += 0.25
        if relay.last_frame is None:
            logger.warning(f"No frame received from {stream_url} after {WARMUP_TIMEOUT}s; closing client.")
            relay.remove_client(client_queue)
            # Send minimal multipart boundary with text to avoid blank image tag
            yield b"--frame\r\nContent-Type: text/plain\r\n\r\nStream unavailable\r\n"
            return
        consecutive_timeouts = 0
        try:
            while relay.running:
                try:
                    chunk = client_queue.get(timeout=QUEUE_TIMEOUT)
                    consecutive_timeouts = 0
                    if chunk is None:
                        logger.info(f"Client queue close signal {stream_url}")
                        break
                    # Wrap raw JPEG if relay did not add multipart boundary
                    if not chunk.startswith(b"--frame"):
                        yield b"--frame\r\nContent-Type: image/jpeg\r\n\r\n" + chunk + b"\r\n"
                    else:
                        yield chunk
                except Exception as e:
                    consecutive_timeouts += 1
                    logger.warning(f"Queue read exception ({e}) for {stream_url}; timeout #{consecutive_timeouts}")
                    if consecutive_timeouts == 3:
                        logger.warning(f"Timeouts x3 reading queue for {stream_url}")
                    if consecutive_timeouts >= MAX_CONSECUTIVE_TIMEOUTS or not relay.running:
                        logger.error(f"Abandoning stream {stream_url}; consecutive_timeouts={consecutive_timeouts}")
                        break
        finally:
            relay.remove_client(client_queue)
            logger.info(f"Client removed from {stream_url}; remaining={len(relay.clients)}")

    return Response(
        generate(),
        mimetype="multipart/x-mixed-replace; boundary=frame",
        headers={
            "Cache-Control": "no-cache, no-store, must-revalidate",
            "Pragma": "no-cache",
            "Expires": "0",
        },
    )

@app.route("/aquaponics/health")
def health():
    """Simple health check used by monitoring or load balancers."""
    return {"status": "ok"}

@app.route("/aquaponics/server_info")
def server_info():
    import threading
    return {
        "server": request.environ.get("SERVER_SOFTWARE", "unknown"),
        "active_threads": len(threading.enumerate()),
        "media_relays": list(_media_relays.keys()),
    }

@app.route("/aquaponics/waitress_info")
def waitress_info():
    """Runtime diagnostics focused on Waitress + streaming load."""
    import threading, platform, sys
    all_threads = threading.enumerate()
    thread_names = [t.name for t in all_threads]
    waitress_threads = [n for n in thread_names if "waitress" in n.lower()]
    relay_stats = {}
    with _media_lock:
        for url, relay in _media_relays.items():
            with relay.lock:
                relay_stats[url] = {
                    "clients": len(relay.clients),
                    "has_frame": relay.last_frame is not None,
                    "running": relay.running,
                }

    return {
        "server_software": request.environ.get("SERVER_SOFTWARE", "unknown"),
        "python": sys.version.split()[0],
        "platform": platform.platform(),
        "utc_epoch": int(time.time()),
        "threads_total": len(all_threads),
        "threads_waitress": len(waitress_threads),
        "waitress_thread_names_sample": waitress_threads[:10],
        "threads_other": len(all_threads) - len(waitress_threads),
        "relays": relay_stats,
    }

# ---------------------------------------------------------------------------
# TEMPLATE CONTEXT
# ---------------------------------------------------------------------------
@app.context_processor
def inject_urls():
    """Makes app_root available in all templates if needed for building links."""
    return dict(app_root=app.config["APPLICATION_ROOT"])

@app.context_processor
def inject_script_root():
    """Make script_root available in all templates for building static URLs"""
    return dict(script_root=request.script_root if request.script_root else '')

# ---------------------------------------------------------------------------
# CLEANUP LOGIC
# ---------------------------------------------------------------------------
def cleanup_relays():
    """Called at shutdown to stop all relay threads cleanly."""
    with _media_lock:
        for relay in _media_relays.values():
            relay.stop()
        _media_relays.clear()
    logger.info("Cached relays cleaned up")

# ---------------------------------------------------------------------------
# GEOIP DATABASE INITIALIZATION
# ---------------------------------------------------------------------------
try:
    import geoip2.database
    GEOIP_DB_PATH = os.path.join(os.path.dirname(__file__), 'geoip', 'GeoLite2-City.mmdb')
    
    geo_reader = None
    if os.path.exists(GEOIP_DB_PATH):
        try:
            geo_reader = geoip2.database.Reader(GEOIP_DB_PATH)
            logger.info(f"GeoIP DB loaded: {GEOIP_DB_PATH}")
        except Exception as e:
            logger.exception(f"Failed to open GeoIP DB ({GEOIP_DB_PATH}): {e}")
            geo_reader = None
    else:
        logger.warning(f"GeoIP DB not found at {GEOIP_DB_PATH}")
except ImportError:
    logger.warning("geoip2 package not installed, geolocation features disabled")
    geo_reader = None

# ---------------------------------------------------------------------------
# MAIN ENTRY POINT
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import atexit
    atexit.register(cleanup_relays)
    print("Development mode ONLY (use waitress_app.py in production).")
    app.run(host="127.0.0.1", port=5000, debug=False)

@app.route("/")
def root_redirect():
    return redirect("/aquaponics/")

@app.route("/aquaponics")
@app.route("/aquaponics/")
def index():
    fish_stream_url = url_for("stream_proxy", path=DEFAULT_STREAM_PATH_0)
    plants_stream_url = url_for("stream_proxy", path=DEFAULT_STREAM_PATH_1)
    return render_template("index.html",
                           fish_stream_url=fish_stream_url,
                           plants_stream_url=plants_stream_url,
                           timestamp=int(time.time()))

@app.route("/aquaponics/stream_probe")
def stream_probe():
    host = request.args.get("host", DEFAULT_STREAM_HOST)
    port = int(request.args.get("port", DEFAULT_STREAM_PORT))
    path = request.args.get("path", DEFAULT_STREAM_PATH_0)
    url = f"http://{host}:{port}{path}"
    import requests, traceback
    info = {"upstream_url": url}
    try:
        r = requests.get(url, timeout=5, stream=True)
        info["status_code"] = r.status_code
        info["content_type"] = r.headers.get("Content-Type")
        # Read a small chunk
        chunk = next(r.iter_content(chunk_size=4096), b"")
        info["first_chunk_len"] = len(chunk)
        info["first_chunk_prefix"] = chunk[:32].hex()
    except Exception as e:
        info["error"] = str(e)
        info["traceback"] = traceback.format_exc()
    return jsonify(info)

@app.route("/aquaponics/relay_dump")
def relay_dump():
    dump = {}
    with _media_lock:
        for url, relay in _media_relays.items():
            with relay.lock:
                dump[url] = {
                    "clients": len(relay.clients),
                    "running": relay.running,
                    "has_frame": relay.last_frame is not None,
                }
    return jsonify(dump)

import logging
for name in ("werkzeug", "flask.app"):
    logging.getLogger(name).setLevel(logging.INFO)
    logging.getLogger(name).propagate = True

@app.before_request
def track_visitor():
    try:
        ip = request.remote_addr
        ua = request.headers.get("User-Agent", "")[:250]
        now = datetime.utcnow()

        v = VisitorLocation.query.filter_by(ip_address=ip).first()
        if v:
            v.last_visit = now
            v.visit_count = (v.visit_count or 0) + 1
            v.user_agent = ua
        else:
            v = VisitorLocation(
                ip_address=ip,
                last_visit=now,
                first_visit=now,
                visit_count=1,
                user_agent=ua,
            )
            db.session.add(v)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        logger.warning(f"Visit not recorded: {e}")
