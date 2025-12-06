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

import logging
import requests
from urllib.parse import unquote, parse_qsl
from fish_cam_config import (
    DEFAULT_STREAM_HOST as CAM_HOST,
    DEFAULT_STREAM_PORT as CAM_PORT,
    DEFAULT_STREAM_PATH_0,
    DEFAULT_STREAM_PATH_1,
)
from geomap_module.routes import VISITOR_COOLDOWN_HOURS
from geomap_module.helpers import get_ip, get_location
from geomap_module.models import VisitorLocation
from geomap_module import geomap_bp
from database import db
from cached_relay import CachedMediaRelay
from dotenv import load_dotenv
import time
import threading
from flask import Flask, render_template, request, url_for, Response, redirect, session, jsonify
from datetime import datetime, timedelta
import os
from logging_config import setup_logging, get_logger

setup_logging("main_app.log")
logger = get_logger("main_app")
logger.info("Application starting...")

# DO NOT reassign logger variable after this point
# All subsequent code should use: logger.info(...) not test_logger.info(...)

# Now import Flask and the rest
# Load environment variables
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
load_dotenv(os.path.join(BASE_DIR, ".env"))

logger.info("Environment variables loaded")  # ADD: confirm this step works

# ---------------------------------------------------------------------------
# STREAM RELAY STATE / CONFIG
# ---------------------------------------------------------------------------
WARMUP_TIMEOUT = 5.0          # seconds to wait for first frame
QUEUE_TIMEOUT = 2.0           # seconds waiting for a frame from client queue
MAX_CONSECUTIVE_TIMEOUTS = 10  # drop client after this many timeouts

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

# Configure session for Turnstile persistence
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=1)
app.config['SESSION_COOKIE_SECURE'] = False  # Set to True if using HTTPS
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

# SECRET KEY MUST BE SET BEFORE INIT_TURNSTILE (because sessions won't work without it)
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

# NOW import and initialize Turnstile (after secret_key is set and after load_dotenv)
from turnstile import init_turnstile
init_turnstile(app)
logger.info("Turnstile initialization attempted")

# Database configuration (adjust if you use a different URI)
INSTANCE_DIR = r"c:/inetpub/aquaponics/instance"
os.makedirs(INSTANCE_DIR, exist_ok=True)

logger.info(f"Instance directory ready: {INSTANCE_DIR}")  # ADD: confirm this step works

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
        db_path = app.config["SQLALCHEMY_DATABASE_URI"].replace(
            "sqlite:///", "", 1)
        logger.info(
            f"Visitors DB ready: {db_path} exists={os.path.exists(db_path)}")
    except Exception as e:
        logger.exception(f"DB init failed: {e}")

logger.info("Database initialization complete")  # ADD: confirm this step works

try:
    app.register_blueprint(geomap_bp, url_prefix='/aquaponics/geomap')
    logger.info("Geomap blueprint registered")  # ADD: confirm this step works
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
    BlogPost = None  # Set to None if import fails, so app doesn't crash

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
# CONTENT SECURITY POLICY FOR THINGSPEAK IFRAMES & TURNSTILE
# ---------------------------------------------------------------------------
# optional for private channel
THINGSPEAK_READ_KEY = os.getenv("THINGSPEAK_READ_KEY")


@app.after_request
def set_security_headers(response):
    """Set Content Security Policy and other security headers."""
    response.headers['Cross-Origin-Resource-Policy'] = 'cross-origin'
    response.headers['Cross-Origin-Embedder-Policy'] = 'unsafe-none'
    path = request.path.rstrip('/')
    
    # Base CSP that allows Cloudflare Turnstile globally
    base_csp = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://challenges.cloudflare.com https://cdn.jsdelivr.net https://cdnjs.cloudflare.com https://unpkg.com; "
        "script-src-elem 'self' 'unsafe-inline' 'unsafe-eval' https://challenges.cloudflare.com https://cdn.jsdelivr.net https://cdnjs.cloudflare.com https://unpkg.com; "
        "style-src 'self' 'unsafe-inline' https://challenges.cloudflare.com https://cdn.jsdelivr.net https://cdnjs.cloudflare.com https://unpkg.com; "
        "style-src-elem 'self' 'unsafe-inline' https://challenges.cloudflare.com https://cdn.jsdelivr.net https://cdnjs.cloudflare.com https://unpkg.com; "
        "img-src 'self' data: https://challenges.cloudflare.com https://img.youtube.com https://unpkg.com https://*.tile.openstreetmap.org; "
        "frame-src 'self' https://challenges.cloudflare.com; "
        "connect-src 'self' https://challenges.cloudflare.com https://cdn.jsdelivr.net; "
        "font-src 'self' data: https://cdn.jsdelivr.net;"
    )
    
    if path == '/aquaponics/sensors':
        # Sensor page CSP - allow ThingSpeak images and content
        response.headers['Content-Security-Policy'] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://challenges.cloudflare.com https://cdn.jsdelivr.net; "
            "script-src-elem 'self' 'unsafe-inline' 'unsafe-eval' https://challenges.cloudflare.com https://cdn.jsdelivr.net; "
            "style-src 'self' 'unsafe-inline' https://challenges.cloudflare.com https://cdn.jsdelivr.net; "
            "style-src-elem 'self' 'unsafe-inline' https://challenges.cloudflare.com https://cdn.jsdelivr.net; "
            "img-src 'self' data: https://challenges.cloudflare.com https://thingspeak.com https://*.thingspeak.com https://mathworks.com https://*.mathworks.com; "
            "frame-src 'self' https://challenges.cloudflare.com https://thingspeak.com https://*.thingspeak.com https://mathworks.com https://*.mathworks.com; "
            "connect-src 'self' https://challenges.cloudflare.com https://cdn.jsdelivr.net https://thingspeak.com https://*.thingspeak.com https://api.thingspeak.com https://mathworks.com https://*.mathworks.com; "
            "font-src 'self' data: https://cdn.jsdelivr.net;"
        )
        response.headers.pop('X-Frame-Options', None)
    else:
        response.headers['Content-Security-Policy'] = base_csp
    
    return response


@app.route("/aquaponics/sensors")
def sensors():
    return render_template("sensors.html", ts_read_key=THINGSPEAK_READ_KEY)


@app.route("/aquaponics/thingspeak_proxy")
def thingspeak_proxy():
    """Proxy Thingspeak resources to avoid CORP blocks."""
    path = request.args.get("path")
    client_ip = request.remote_addr or request.environ.get("REMOTE_ADDR")
    logger.info("Thingspeak proxy request from %s path=%s", client_ip, path)

    if not path:
        logger.warning("Thingspeak proxy missing 'path' from %s", client_ip)
        return ("Missing 'path' parameter", 400)
    if ".." in path or path.startswith("//"):
        logger.warning("Thingspeak proxy invalid path from %s: %s", client_ip, path)
        return ("Invalid path", 400)

    decoded = unquote(path)
    if "?" in decoded:
        path_part, query_str = decoded.split("?", 1)
        params = dict(parse_qsl(query_str, keep_blank_values=True))
    else:
        path_part = decoded
        params = None

    if path_part.startswith("/"):
        url = f"https://thingspeak.com{path_part}"
    else:
        url = f"https://thingspeak.com/{path_part}"

    logger.info("Thingspeak proxy forwarding to %s params=%s (client=%s)", url, params, client_ip)
    try:
        start = time.time()
        resp = requests.get(url, params=params, timeout=15)
        elapsed = time.time() - start
        logger.info(
            "Thingspeak responded %s bytes=%d in %.3fs for client %s",
            resp.status_code,
            len(resp.content or b""),
            elapsed,
            client_ip,
        )
    except Exception:
        logger.exception("Thingspeak proxy request failed for url=%s (client=%s)", url, client_ip)
        return ("Upstream request failed", 502)

    # Headers to exclude (blocking headers)
    excluded = {
        "content-encoding",
        "transfer-encoding",
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailers",
        "upgrade",
        "x-frame-options",
        "content-security-policy",
    }

    response = Response(resp.content, status=resp.status_code)
    for k, v in resp.headers.items():
        if k.lower() in excluded or k.lower() == "content-length":
            continue
        response.headers[k] = v

    # Add headers to allow framing
    response.headers['X-Frame-Options'] = 'ALLOWALL'
    response.headers['Access-Control-Allow-Origin'] = '*'
    
    return response


@app.route("/aquaponics/assets/<path:asset_path>")
def thingspeak_assets_proxy(asset_path):
    """Proxy Thingspeak assets (JS, CSS, images) that widgets try to load."""
    url = f"https://thingspeak.com/assets/{asset_path}"
    logger.info("Proxying Thingspeak asset: %s", url)
    try:
        resp = requests.get(url, timeout=10)
        content_type = resp.headers.get("Content-Type", "application/octet-stream")
        response = Response(resp.content, status=resp.status_code, mimetype=content_type)
        response.headers["Cache-Control"] = "public, max-age=3600"
        return response
    except Exception:
        logger.exception("Failed to proxy Thingspeak asset: %s", url)
        return ("Asset not found", 404)


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
    # Get the path parameter from query string
    path = request.args.get("path", DEFAULT_STREAM_PATH_0)
    
    # FIX: Strip any query parameters from the path before forwarding to camera
    # The browser adds ?t=timestamp for cache-busting, but camera doesn't understand it
    if '?' in path:
        path = path.split('?')[0]
    
    host = DEFAULT_STREAM_HOST
    port = DEFAULT_STREAM_PORT
    
    # Build clean upstream URL without query parameters
    stream_url = f"http://{host}:{port}{path}"
    
    logger.info(f"Proxy upstream={stream_url}")
    relay = get_media_relay(stream_url)
    client_queue = relay.add_client()
    logger.info(
        f"Added client to relay {stream_url}; total_clients={len(relay.clients)}")

    def generate():
        waited = 0.0
        # Wait for first frame
        while relay.last_frame is None and waited < WARMUP_TIMEOUT and relay.running:
            time.sleep(0.25)
            waited += 0.25
        if relay.last_frame is None:
            logger.warning(
                f"No frame received from {stream_url} after {WARMUP_TIMEOUT}s; closing client.")
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
                    logger.warning(
                        f"Queue read exception ({e}) for {stream_url}; timeout #{consecutive_timeouts}")
                    if consecutive_timeouts == 3:
                        logger.warning(
                            f"Timeouts x3 reading queue for {stream_url}")
                    if consecutive_timeouts >= MAX_CONSECUTIVE_TIMEOUTS or not relay.running:
                        logger.error(
                            f"Abandoning stream {stream_url}; consecutive_timeouts={consecutive_timeouts}")
                        break
        finally:
            relay.remove_client(client_queue)
            logger.info(
                f"Client removed from {stream_url}; remaining={len(relay.clients)}")

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
    import threading
    import platform
    import sys
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
    GEOIP_DB_PATH = os.path.join(os.path.dirname(
        __file__), 'geoip', 'GeoLite2-City.mmdb')

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
    logger.warning(
        "geoip2 package not installed, geolocation features disabled")
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
    """Landing page for the Aquaponics monitoring system."""
    logger.info("Index page accessed")
    
    # FIX: Swap these - stream0 is fish, stream1 is plants
    fish_stream_url = url_for("stream_proxy", path=DEFAULT_STREAM_PATH_0, _external=False)
    plants_stream_url = url_for("stream_proxy", path=DEFAULT_STREAM_PATH_1, _external=False)
    
    # Get latest blog posts
    latest_posts = []
    try:
        from blog.models import BlogPost
        latest_posts = BlogPost.query.order_by(BlogPost.created_at.desc()).limit(2).all()
        logger.info(f"Loaded {len(latest_posts)} blog posts for index page")
    except Exception as e:
        logger.warning(f"Could not load blog posts: {e}")
    
    return render_template("index.html",
                           fish_stream_url=fish_stream_url,
                           plants_stream_url=plants_stream_url,
                           latest_posts=latest_posts,
                           timestamp=int(time.time()))


@app.route("/aquaponics/stream_probe")
def stream_probe():
    host = request.args.get("host", DEFAULT_STREAM_HOST)
    port = int(request.args.get("port", DEFAULT_STREAM_PORT))
    path = request.args.get("path", DEFAULT_STREAM_PATH_0)
    url = f"http://{host}:{port}{path}"
    import requests
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


for name in ("werkzeug", "flask.app"):
    logging.getLogger(name).setLevel(logging.INFO)
    logging.getLogger(name).propagate = True


@app.before_request
def track_visitor():
    try:
        ip = request.remote_addr
        ua = request.headers.get("User-Agent", "")[:250]
        now = datetime.utcnow()

        # FIX: Query from the visitors database using bind_key
        v = db.session.query(VisitorLocation).filter_by(ip_address=ip).first()
        if v:
            v.last_visit = now
            v.visit_count = (v.visit_count or 0) + 1
            v.user_agent = ua
            logger.debug(f"Updated visitor: {ip}")
        else:
            v = VisitorLocation(
                ip_address=ip,
                last_visit=now,
                first_visit=now,
                visit_count=1,
                user_agent=ua,
            )
            db.session.add(v)
            logger.info(f"New visitor tracked: {ip}")
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        logger.exception(f"Visit not recorded: {e}")  # Changed to exception for full traceback


@app.route("/aquaponics/visitors")
def visitors():
    """Display visitor tracking information from the database."""
    try:
        # FIX: Query from the visitors database
        all_visitors = db.session.query(VisitorLocation).order_by(
            VisitorLocation.last_visit.desc()
        ).all()
        
        # Get total visit count (sum of all visit_count fields)
        total_visitors = db.session.query(
            db.func.sum(VisitorLocation.visit_count)
        ).scalar() or 0
        
        # Get unique visitor count
        unique_visitors = db.session.query(VisitorLocation).count()
        
        logger.info(f"Visitors page accessed: {unique_visitors} unique, {total_visitors} total visits")
        logger.info(f"Sample visitor data: {all_visitors[:3] if all_visitors else 'No visitors'}")
        
        return render_template(
            "visitors.html",
            visitors=all_visitors,
            total_visitors=total_visitors,
            unique_visitors=unique_visitors
        )
    except Exception as e:
        logger.exception(f"Error loading visitors page: {e}")
        return render_template("error.html", message="Could not load visitor data"), 500


@app.route("/aquaponics/videos")
def videos_static():
    """Redirect to blog videos page."""
    return redirect(url_for("blog_bp.videos"))


@app.route("/aquaponics/thingspeak_api")
def thingspeak_api():
    """Proxy ThingSpeak API requests to avoid CORS blocks."""
    channel_id = request.args.get("channel_id")
    
    if not channel_id:
        return ("Missing 'channel_id' parameter", 400)
    
    url = f"https://api.thingspeak.com/channels/{channel_id}/feeds/last.json"
    
    try:
        resp = requests.get(url, timeout=10)
        response = Response(resp.content, status=resp.status_code, mimetype="application/json")
        response.headers['Access-Control-Allow-Origin'] = '*'
        return response
    except Exception:
        logger.exception("ThingSpeak API proxy request failed for channel=%s", channel_id)
        return ("API request failed", 502)
