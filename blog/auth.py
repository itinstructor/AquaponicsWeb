import re
from flask import request
import logging


def validate_password(password):
    """
    Validate password meets requirements of 3 out of 4:
    - At least 8 characters
    - At least one uppercase letter
    - At least one lowercase letter
    - At least one number
    Returns: (is_valid: bool, error_message: str)
    """
    if len(password) < 8:
        return False, "Password must be at least 8 characters long"
    if not re.search(r'[A-Z]', password):
        return False, "Password must contain at least one uppercase letter"
    if not re.search(r'[a-z]', password):
        return False, "Password must contain at least one lowercase letter"
    if not re.search(r'\d', password):
        return False, "Password must contain at least one number"
    return True, ""


def get_client_ip():
    """Get the real client IP address."""
    from flask import request
    
    # Check X-Forwarded-For header (set by IIS/reverse proxies)
    x_forwarded_for = request.headers.get('X-Forwarded-For')
    if x_forwarded_for:
        client_ip = x_forwarded_for.split(',')[0].strip()
        return client_ip
    
    # Fallback to other headers
    if request.headers.get('X-Real-IP'):
        return request.headers.get('X-Real-IP')
    
    return request.remote_addr


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


