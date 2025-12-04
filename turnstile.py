"""
Cloudflare Turnstile integration for bot protection.
"""
import os
import time
import requests
from flask import request, session, render_template_string, redirect, url_for
from typing import Dict, Optional
from logging_config import get_logger

logger = get_logger(__name__)

# Note: Environment variables should be loaded by main_app.py before importing this module
# No need to call load_dotenv here - rely on os.environ being populated

# Configuration from environment - support both naming conventions
TURNSTILE_SITE_KEY = (
    os.environ.get("TURNSTILE_SITE_KEY") or 
    os.environ.get("TURNSTILE_SITEKEY")
)
TURNSTILE_SECRET = (
    os.environ.get("TURNSTILE_SECRET") or 
    os.environ.get("TURNSTILE_SECRET_KEY")
)
TURNSTILE_VERIFY_TTL = int(os.environ.get("TURNSTILE_VERIFY_TTL", "86400"))  # 24 hours default
TURNSTILE_ENABLED = bool(TURNSTILE_SITE_KEY and TURNSTILE_SECRET)

TURNSTILE_VERIFY_URL = "https://challenges.cloudflare.com/turnstile/v0/siteverify"

# Session key for storing verification timestamp
SESSION_VERIFIED_KEY = "_turnstile_verified_at"


# Challenge page HTML template with Aquaponics branding
CHALLENGE_PAGE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Verification - Aquaponics System</title>
    <script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.8/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        body {
            background: #000;
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
        }
        .challenge-card {
            background: #23272f;
            border-radius: 1rem;
            box-shadow: 0 20px 60px rgba(0,0,0,0.5);
            max-width: 500px;
            width: 100%;
        }
        .card-header {
            background: linear-gradient(135deg, #222c3c 0%, #2a5298 100%);
            color: #fff;
            border-radius: 1rem 1rem 0 0 !important;
            padding: 2rem;
            text-align: center;
        }
        .card-body {
            padding: 2rem;
            color: #e0e0e0;
        }
        .turnstile-container {
            display: flex;
            justify-content: center;
            margin: 2rem 0;
        }
        .spinner-border {
            display: none;
        }
        .error-message {
            display: none;
        }
        {% if error %}
        .error-message {
            display: block;
        }
        {% endif %}
        .alert {
            background: #2d323c;
            color: #ffb4b4;
            border: 1px solid #ffb4b4;
        }
        .text-muted {
            color: #b0b8c1 !important;
        }
        .btn-primary {
            background-color: #2a5298;
            border-color: #2a5298;
        }
    </style>
</head>
<body>
    <div class="challenge-card">
        <div class="card-header">
            <h2 class="mb-0">🔒 Security Verification</h2>
            <p class="mb-0 mt-2">WNCC Aquaponics System</p>
        </div>
        <div class="card-body text-center">
            <p class="text-muted mb-3">Please complete this quick security check to access the aquaponics dashboard.</p>
            
            {% if error %}
            <div class="alert alert-danger error-message" role="alert">
                <strong>⚠️ Verification Failed</strong><br>
                Please try again.
            </div>
            {% endif %}
            
            <form id="challenge-form" method="POST" action="{{ verify_url }}">
                <input type="hidden" name="next" value="{{ next_url }}">
                <div class="turnstile-container">
                    <div class="cf-turnstile" 
                         data-sitekey="{{ site_key }}"
                         data-callback="onTurnstileSuccess"
                         data-error-callback="onTurnstileError"
                         data-theme="dark"></div>
                </div>
            </form>
            
            <div id="status-container">
                <div class="spinner-border text-primary" id="spinner" role="status">
                    <span class="visually-hidden">Verifying...</span>
                </div>
            </div>
            
            <p class="text-muted small mt-3">This verification helps protect our system from automated abuse.</p>
        </div>
    </div>

    <script>
        let formSubmitted = false;
        
        function onTurnstileSuccess(token) {
            if (formSubmitted) return;
            formSubmitted = true;
            
            console.log('Turnstile verification successful');
            document.getElementById('spinner').style.display = 'inline-block';
            
            // Auto-submit after short delay
            setTimeout(() => {
                document.getElementById('challenge-form').submit();
            }, 300);
        }
        
        function onTurnstileError(error) {
            console.error('Turnstile error:', error);
            const errorDiv = document.createElement('div');
            errorDiv.className = 'alert alert-warning mt-3';
            errorDiv.innerHTML = '⚠️ Verification error. <a href="javascript:location.reload()">Please try again</a>';
            document.getElementById('status-container').appendChild(errorDiv);
        }
    </script>
</body>
</html>
"""


def validate_turnstile(token: str, remoteip: Optional[str] = None) -> Dict:
    """
    Validate a Turnstile token with Cloudflare's API.
    
    Returns dict with 'success' boolean and optional 'error-codes' list.
    """
    if not TURNSTILE_SECRET:
        logger.error("TURNSTILE_SECRET not configured")
        return {"success": False, "error-codes": ["missing-secret"]}
    
    if not token:
        logger.warning(f"Missing Turnstile token from {remoteip}")
        return {"success": False, "error-codes": ["missing-token"]}
    
    payload = {
        "secret": TURNSTILE_SECRET,
        "response": token,
    }
    if remoteip:
        payload["remoteip"] = remoteip
    
    try:
        resp = requests.post(TURNSTILE_VERIFY_URL, data=payload, timeout=10)
        if resp.ok:
            result = resp.json()
            if result.get("success"):
                logger.info(f"Turnstile verification SUCCESS for {remoteip}")
            else:
                logger.warning(f"Turnstile verification FAILED for {remoteip}: {result.get('error-codes')}")
            return result
        else:
            logger.warning(f"Turnstile API returned {resp.status_code}: {resp.text[:200]}")
            return {"success": False, "error-codes": ["api-error"]}
    except Exception as e:
        logger.exception(f"Turnstile validation exception for {remoteip}: {e}")
        return {"success": False, "error-codes": [f"exception:{str(e)}"]}


def is_turnstile_verified() -> bool:
    """Check if current session has a valid Turnstile verification."""
    # Check dynamically, not using module constant
    site_key = os.environ.get("TURNSTILE_SITE_KEY") or os.environ.get("TURNSTILE_SITEKEY")
    secret = os.environ.get("TURNSTILE_SECRET") or os.environ.get("TURNSTILE_SECRET_KEY")
    
    if not (site_key and secret):
        logger.warning("Turnstile: Not configured (missing keys), allowing all")
        return True  # If Turnstile not configured, allow all
    
    verified_at = session.get(SESSION_VERIFIED_KEY)
    
    if not verified_at:
        logger.info("Turnstile: No verification in session, challenge needed")
        return False
    
    # Check if verification has expired
    age = time.time() - verified_at
    is_valid = age < TURNSTILE_VERIFY_TTL
    
    if not is_valid:
        logger.info(f"Turnstile session expired (age: {age:.0f}s, TTL: {TURNSTILE_VERIFY_TTL}s)")
    
    return is_valid


def mark_turnstile_verified():
    """Mark current session as Turnstile-verified."""
    session[SESSION_VERIFIED_KEY] = time.time()
    session.permanent = True
    logger.info(f"Turnstile session marked verified, expires in {TURNSTILE_VERIFY_TTL}s")


def get_client_ip() -> str:
    """Extract client IP, respecting Cloudflare and proxy headers."""
    return (
        request.headers.get("CF-Connecting-IP") or
        request.headers.get("X-Forwarded-For", "").split(",")[0].strip() or
        request.headers.get("X-Real-IP") or
        request.remote_addr or
        "unknown"
    )


def init_turnstile(app):
    """
    Initialize Turnstile protection for the Flask app.
    Adds middleware to check verification on all requests.
    """
    # Check dynamically, not using module constant
    site_key = os.environ.get("TURNSTILE_SITE_KEY") or os.environ.get("TURNSTILE_SITEKEY")
    secret = os.environ.get("TURNSTILE_SECRET") or os.environ.get("TURNSTILE_SECRET_KEY")
    
    if not (site_key and secret):
        logger.warning("⚠️ Turnstile NOT enabled (missing TURNSTILE_SITE_KEY or TURNSTILE_SECRET)")
        return
    
    logger.info(f"✓ Turnstile enabled with site key: {site_key[:10]}... (TTL: {TURNSTILE_VERIFY_TTL}s)")
    
    # Get the application root for proper URL construction
    app_root = app.config.get('APPLICATION_ROOT', '/aquaponics')
    
    # Register routes with explicit paths (not f-strings in decorators)
    turnstile_verify_path = app_root + "/turnstile/verify"
    turnstile_challenge_path = app_root + "/turnstile/challenge"
    
    logger.info(f"Registering Turnstile routes: {turnstile_verify_path}, {turnstile_challenge_path}")
    
    # Add verification endpoint
    @app.route(turnstile_verify_path, methods=["POST"])
    def turnstile_verify():
        """Process Turnstile verification and redirect back."""
        token = request.form.get("cf-turnstile-response")
        next_url = request.form.get("next", app_root + "/")
        client_ip = get_client_ip()
        
        logger.info(f"Turnstile verify POST from {client_ip}, token={'present' if token else 'MISSING'}")
        
        validation = validate_turnstile(token, client_ip)
        
        if validation.get("success"):
            mark_turnstile_verified()
            logger.info(f"Turnstile: Verified user redirecting to {next_url}")
            return redirect(next_url)
        else:
            errors = validation.get("error-codes", [])
            logger.warning(f"Turnstile: Challenge failed, showing again. Errors: {errors}")
            # Show challenge again with error - use dynamic site_key
            return render_template_string(
                CHALLENGE_PAGE,
                site_key=site_key,
                verify_url=url_for("turnstile_verify"),
                next_url=next_url,
                error=True
            )
    
    # Add challenge page endpoint
    @app.route(turnstile_challenge_path)
    def turnstile_challenge():
        """Show the Turnstile challenge page."""
        next_url = request.args.get("next", app_root + "/")
        logger.info(f"Turnstile: Showing challenge page, next={next_url}")
        # Use dynamic site_key
        return render_template_string(
            CHALLENGE_PAGE,
            site_key=site_key,
            verify_url=url_for("turnstile_verify"),
            next_url=next_url,
            error=False
        )
    
    # Add middleware to check verification before each request
    @app.before_request
    def check_turnstile_verification():
        """
        Middleware to verify Turnstile for all requests.
        Skips static files, health checks, and Turnstile endpoints.
        """
        try:
            path = request.path or ""
            logger.info(f"Turnstile middleware: checking path={path}")
            
            # Skip verification for these paths
            skip_paths = [
                app_root + "/turnstile/",
                app_root + "/static/",
                app_root + "/health",
                app_root + "/server_info",
                app_root + "/waitress_info",
            ]
            
            if any(path.startswith(p) for p in skip_paths):
                return
            
            # Check if already verified
            if is_turnstile_verified():
                logger.info("Turnstile: Session already verified")
                return
            
            # Not verified - redirect to challenge page
            logger.info(f"Turnstile: Challenge required for {path} from {get_client_ip()}")
            return redirect(url_for("turnstile_challenge", next=request.url))
            
        except Exception as e:
            logger.exception(f"Turnstile middleware error: {e}")
            # On error, allow the request to proceed
            return
    
    logger.info("Turnstile middleware registered successfully")
