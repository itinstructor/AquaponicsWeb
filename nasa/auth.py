import re
from flask import request
import logging


def validate_password(password):
    """
    Validate password meets requirements:
    - At least 16 characters
    - At least 3 of 4 categories: uppercase, lowercase, number, symbol
    
    Returns: (is_valid: bool, error_message: str)
    """
    if len(password) < 16:
        return False, "Password must be at least 16 characters long"
    
    categories = 0
    has_upper = bool(re.search(r'[A-Z]', password))
    has_lower = bool(re.search(r'[a-z]', password))
    has_digit = bool(re.search(r'\d', password))
    has_symbol = bool(re.search(r'[^A-Za-z0-9]', password))
    
    if has_upper:
        categories += 1
    if has_lower:
        categories += 1
    if has_digit:
        categories += 1
    if has_symbol:
        categories += 1
    
    if categories < 3:
        return False, "Password must contain at least 3 of: uppercase, lowercase, number, symbol"
    
    return True, ""


def get_client_ip():
    """Get client IP from request headers (respects proxies)."""
    hdr = request.headers.get
    for h in ("X-Real-Ip", "X-Real-IP", "X-Forwarded-For", "X-MS-Forwarded-Client-IP"):
        v = hdr(h)
        if v:
            return v.split(",")[0].strip()
    return request.environ.get("REMOTE_ADDR") or request.remote_addr


def log_login_attempt(username, success, user_agent=None):
    """Log login attempt to database."""
    from .models import LoginAttempt
    from database import db
    
    try:
        attempt = LoginAttempt(
            username=username,
            ip_address=get_client_ip(),
            success=success,
            user_agent=user_agent or request.headers.get('User-Agent', '')[:255]
        )
        db.session.add(attempt)
        db.session.commit()
    except Exception:
        logging.exception("Failed to log login attempt")
        db.session.rollback()


