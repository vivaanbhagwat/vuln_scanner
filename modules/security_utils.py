"""Security Utilities - Rate limiting and other defensive measures."""
from functools import wraps
from flask import request, abort, flash
import time

# Simple in-memory rate limiting (IP-based)
# Production apps should use Redis or similar
_rate_limit_storage = {}

def rate_limit(limit=5, period=60):
    """
    Simple rate limiting decorator.
    Limit: maximum requests allowed.
    Period: time window in seconds.
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            ip = request.remote_addr
            now = time.time()
            
            if ip not in _rate_limit_storage:
                _rate_limit_storage[ip] = []
            
            # Remove old timestamps
            _rate_limit_storage[ip] = [t for t in _rate_limit_storage[ip] if t > now - period]
            
            if len(_rate_limit_storage[ip]) >= limit:
                print(f"[!] Security Alert: Rate limit exceeded for IP {ip} on {request.path}")
                # We don't flash here because abort(429) will lead to a dedicated page
                abort(429)
            
            _rate_limit_storage[ip].append(now)
            return f(*args, **kwargs)
        return decorated_function
    return decorator
