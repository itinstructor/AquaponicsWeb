"""
Cloudflare Turnstile integration for bot protection.

This module provides site-wide Turnstile verification with session-based caching
to avoid re-challenging verified users on every request.

Features:
- Automatic verification for all non-static routes
- Session-based verification caching (verified users aren't re-challenged)
- Configurable TTL for verification sessions
- Challenge page with auto-redirect after verification

Setup:
1. Get your Turnstile site key and secret key from Cloudflare dashboard
2. Add keys to .env file in project root:
   TURNSTILE_SITE_KEY=your-site-key
   TURNSTILE_SECRET=your-secret-key
   TURNSTILE_VERIFY_TTL=86400
3. Keys are automatically loaded from .env file

Usage:
    from turnstile import init_turnstile
    
    # Initialize in your Flask app
    init_turnstile(app)
    
    # Middleware automatically protects all routes
"""
import os
import time
import requests
from flask import request, session, render_template_string, redirect, url_for
from typing import Dict, Optional
from logging_config import get_logger

logger = get_logger(__name__)

# Load environment variables from .env file
try:
    from dotenv import load_dotenv
    env_path = os.path.join(os.path.dirname(__file__), '.env')
    if os.path.exists(env_path):
        load_dotenv(env_path)
        logger.info(f"Turnstile: Loaded environment from {env_path}")
except ImportError:
    logger.warning("python-dotenv not installed. Using environment variables only.")

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
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        body {
            background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
        }
        .challenge-card {
            background: white;
            border-radius: 1rem;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            max-width: 500px;
            width: 100%;
        }
        .card-header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border-radius: 1rem 1rem 0 0 !important;
            padding: 2rem;
            text-align: center;
        }
        .card-body {
            padding: 2rem;
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
                         data-theme="auto"></div>
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
    if not TURNSTILE_ENABLED:
        return True  # If Turnstile not configured, allow all
    
    verified_at = session.get(SESSION_VERIFIED_KEY)
    if not verified_at:
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
    if not TURNSTILE_ENABLED:
        logger.warning("⚠️ Turnstile NOT enabled (missing TURNSTILE_SITE_KEY or TURNSTILE_SECRET)")
        return
    
    logger.info(f"✓ Turnstile enabled with site key: {TURNSTILE_SITE_KEY[:10]}... (TTL: {TURNSTILE_VERIFY_TTL}s)")
    
    # Get the application root for proper URL construction
    app_root = app.config.get('APPLICATION_ROOT', '').rstrip('/')
    
    # Add verification endpoint
    @app.route(f"{app_root}/turnstile/verify", methods=["POST"])
    def turnstile_verify():
        """Process Turnstile verification and redirect back."""
        token = request.form.get("cf-turnstile-response")
        next_url = request.form.get("next", f"{app_root}/")
        client_ip = get_client_ip()
        
        logger.info(f"Turnstile verify POST from {client_ip}, token={'present' if token else 'MISSING'}")
        
        validation = validate_turnstile(token, client_ip)
        
        if validation.get("success"):
            mark_turnstile_verified()
            logger.info(f"Redirecting verified user to: {next_url}")
            return redirect(next_url)
        else:
            errors = validation.get("error-codes", [])
            logger.warning(f"Showing challenge again due to errors: {errors}")
            # Show challenge again with error
            return render_template_string(
                CHALLENGE_PAGE,
                site_key=TURNSTILE_SITE_KEY,
                verify_url=url_for("turnstile_verify"),
                next_url=next_url,
                error=True
            )
    
    # Add challenge page endpoint
    @app.route(f"{app_root}/turnstile/challenge")
    def turnstile_challenge():
        """Show the Turnstile challenge page."""
        next_url = request.args.get("next", f"{app_root}/")
        logger.info(f"Showing Turnstile challenge, next={next_url}")
        return render_template_string(
            CHALLENGE_PAGE,
            site_key=TURNSTILE_SITE_KEY,
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
        if not TURNSTILE_ENABLED:
            return
        
        path = request.path or ""
        
        # Skip verification for these paths
        app_root = app.config.get('APPLICATION_ROOT', '').rstrip('/')
        skip_paths = [
            f"{app_root}/turnstile/",
            f"{app_root}/static/",
            f"{app_root}/health",
            f"{app_root}/server_info",
            f"{app_root}/waitress_info",
        ]
        
        if any(path.startswith(p) for p in skip_paths):
            return
        
        # Check if already verified
        if is_turnstile_verified():
            return
        
        # Not verified - redirect to challenge page
        logger.info(f"Turnstile verification required for {get_client_ip()} accessing {path}")
        return redirect(url_for("turnstile_challenge", next=request.url))
    
    logger.info("Turnstile middleware registered")
