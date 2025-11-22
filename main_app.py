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

from flask import Flask, render_template, request, url_for, Response, redirect, session, jsonify
import os
import threading
import time
from typing import Dict
from datetime import datetime, timedelta, timezone
from dotenv import load_dotenv

# Load environment variables
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
load_dotenv(os.path.join(BASE_DIR, ".env"))

# Initialize logging FIRST before any other imports
from logging_config import setup_logging, get_logger
setup_logging("main_app.log")
logger = get_logger(__name__)

logger.info("Application starting...")

# Local modules that handle pulling frames from upstream cameras
from cached_relay import CachedMediaRelay

# Database and visitor tracking
from database import db
from geomap_module import geomap_bp
from geomap_module.models import VisitorLocation
from geomap_module.helpers import get_ip, get_location
from geomap_module.routes import VISITOR_COOLDOWN_HOURS

# Turnstile bot protection
from turnstile import init_turnstile

# ---------------------------------------------------------------------------
# FLASK APP SETUP
# ---------------------------------------------------------------------------
app = Flask(__name__, 
           static_folder='static',
           static_url_path='/aquaponics/static')

app.config['APPLICATION_ROOT'] = '/aquaponics'

# ---------------------------------------------------------------------------
# DATABASE SETUP
# ---------------------------------------------------------------------------
os.makedirs(app.instance_path, exist_ok=True)

VISITORS_DB_PATH = os.path.join(app.instance_path, "visitors.db")

app.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{VISITORS_DB_PATH}"
app.config["SQLALCHEMY_BINDS"] = {"visitors": f"sqlite:///{VISITORS_DB_PATH}"}
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# Set secret key for sessions
SECRET_KEY_FILE = os.path.join(os.path.dirname(__file__), "secret_key.txt")

if os.path.exists(SECRET_KEY_FILE):
    with open(SECRET_KEY_FILE, "r", encoding="utf-8") as f:
        app.config["SECRET_KEY"] = f.read().strip().lstrip('\ufeff')  # Remove BOM
    logger.info("Secret key loaded from file")
else:
    logger.error("secret_key.txt not found! Run generate_secret_key.py first")
    raise RuntimeError(
        "Secret key file missing. Run generate_secret_key.py to create it."
    )

# Initialize the database with this app
db.init_app(app)

# Register the geomap blueprint for visitor tracking
app.register_blueprint(geomap_bp, url_prefix="/aquaponics")

# Create database tables if they don't exist
with app.app_context():
    try:
        db.create_all()
        logger.info("Database tables created/verified")
    except Exception as e:
        logger.exception("Failed to create database tables")

# ---------------------------------------------------------------------------
# INITIALIZE TURNSTILE PROTECTION
# ---------------------------------------------------------------------------
init_turnstile(app)

# ---------------------------------------------------------------------------
# VISITOR TRACKING MIDDLEWARE
# ---------------------------------------------------------------------------
@app.before_request
def track_visitor():
    """
    Middleware to track visitor IP locations on each request.
    Runs before every request to log visitor information.
    Increments visit counter for returning visitors.
    """
    # Skip tracking for static files, API endpoints, health checks, and Turnstile
    if (
        request.path.startswith("/aquaponics/static/")
        or request.path.startswith("/aquaponics/api/")
        or request.path.startswith("/aquaponics/turnstile/")
        or request.path in [
            "/aquaponics/health",
            "/aquaponics/server_info",
            "/aquaponics/waitress_info",
        ]
        or request.path == "/aquaponics/stream_proxy"
    ):
        return

    now_utc = datetime.now(timezone.utc)

    try:
        ip = get_ip()
        existing_visitor = VisitorLocation.query.filter_by(ip_address=ip).first()

        if existing_visitor:
            last_visit = existing_visitor.last_visit
            if last_visit and last_visit.tzinfo is None:
                last_visit = last_visit.replace(tzinfo=timezone.utc)

            recent_cutoff = now_utc - timedelta(hours=VISITOR_COOLDOWN_HOURS)
            if last_visit and last_visit > recent_cutoff:
                return

            existing_visitor.increment_visit(
                page_visited=request.path,
                user_agent=request.headers.get("User-Agent", "")[:255],
            )
            db.session.commit()
            logger.info(f"Updated visitor from {ip} - Visit #{existing_visitor.visit_count}")
        else:
            logger.info(f"New visitor {ip}, fetching location data...")
            location_data = get_location(ip)

            visitor = VisitorLocation(
                ip_address=ip,
                lat=location_data.get("lat") if location_data else 0.0,
                lon=location_data.get("lon") if location_data else 0.0,
                city=location_data.get("city") if location_data else None,
                region=location_data.get("region") if location_data else None,
                country=location_data.get("country") if location_data else None,
                country_code=(location_data.get("country_code") if location_data else None),
                continent=(location_data.get("continent") if location_data else None),
                zipcode=location_data.get("zipcode") if location_data else None,
                isp=location_data.get("isp") if location_data else None,
                organization=(location_data.get("organization") if location_data else None),
                timezone=(location_data.get("timezone") if location_data else None),
                currency=(location_data.get("currency") if location_data else None),
                user_agent=request.headers.get("User-Agent", "")[:255],
                page_visited=request.path,
            )

            db.session.add(visitor)
            db.session.commit()
            logger.info(f"Successfully tracked new visitor from {ip}")

    except Exception as e:
        logger.error(f"Error tracking visitor: {e}", exc_info=True)
        db.session.rollback()

# ---------------------------------------------------------------------------
# CAMERA CONFIGURATION
# ---------------------------------------------------------------------------
DEFAULT_STREAM_HOST = "10.0.0.2"
DEFAULT_STREAM_PORT = 8000
DEFAULT_STREAM_PATH_0 = "/stream0.mjpg"  # Fish tank
DEFAULT_STREAM_PATH_1 = "/stream1.mjpg"  # Plant bed

# ---------------------------------------------------------------------------
# RELAY / STREAMING TUNING
# ---------------------------------------------------------------------------
WIRELESS_CACHE_DURATION = 15.0
WIRELESS_SERVE_DELAY = 2.0
WARMUP_TIMEOUT = 15
MAX_CONSECUTIVE_TIMEOUTS = 10
QUEUE_TIMEOUT = 15

_media_relays: Dict[str, CachedMediaRelay] = {}
_media_lock = threading.Lock()


def get_media_relay(stream_url: str) -> CachedMediaRelay:
    with _media_lock:
        relay = _media_relays.get(stream_url)
        if relay is None:
            relay = CachedMediaRelay(
                stream_url,
                cache_duration=WIRELESS_CACHE_DURATION,
                serve_delay=WIRELESS_SERVE_DELAY,
            )
            relay.start()
            _media_relays[stream_url] = relay
            logger.info(f"[CachedRelayFactory] Created {stream_url}")
        return relay


# ---------------------------------------------------------------------------
# ROUTES: WEB PAGES
# ---------------------------------------------------------------------------
@app.route("/aquaponics")
@app.route("/aquaponics/")
def index():
    """Main page with camera streams."""
    fish_stream_url = url_for(
        "stream_proxy", path=DEFAULT_STREAM_PATH_0
    )
    plants_stream_url = url_for(
        "stream_proxy", path=DEFAULT_STREAM_PATH_1
    )

    return render_template(
        "index.html",
        fish_stream_url=fish_stream_url,
        plants_stream_url=plants_stream_url,
        timestamp=int(time.time()),
    )

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

@app.route("/aquaponics/sensors")
def sensors():
    """Sensor dashboard page (template only here)."""
    return render_template("sensors.html")

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
@app.route("/aquaponics/stream_proxy")
def stream_proxy():
    """Proxies an upstream MJPEG stream through this server."""
    host = request.args.get("host", DEFAULT_STREAM_HOST)
    port = int(request.args.get("port", DEFAULT_STREAM_PORT))
    path = request.args.get("path", DEFAULT_STREAM_PATH_0)

    stream_url = f"http://{host}:{port}{path}"
    relay = get_media_relay(stream_url)
    client_queue = relay.add_client()

    def generate():
        waited = 0.0
        while relay.last_frame is None and waited < WARMUP_TIMEOUT and relay.running:
            time.sleep(0.2)
            waited += 0.2
        if relay.last_frame is None:
            relay.remove_client(client_queue)
            return
        consecutive_timeouts = 0
        try:
            while relay.running:
                try:
                    chunk = client_queue.get(timeout=QUEUE_TIMEOUT)
                    consecutive_timeouts = 0
                    if chunk is None:
                        break
                    yield chunk
                except Exception:
                    consecutive_timeouts += 1
                    if consecutive_timeouts >= MAX_CONSECUTIVE_TIMEOUTS or not relay.running:
                        break
        finally:
            relay.remove_client(client_queue)

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
