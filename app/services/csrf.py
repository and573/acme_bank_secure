"""CSRF protection for ACME Bank."""

import secrets
from functools import wraps
from typing import Callable
from flask import session, request, flash, redirect, url_for


class CSRFError(Exception):
    """Custom CSRF Exception."""
    pass


def generate_csrf_token() -> str:
    """Generate a new CSRF token if none exists."""
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_urlsafe(32)
    return session.get('csrf_token')


def csrf_protect(func: Callable) -> Callable:
    """Require CSRF token validation on POST requests."""
    @wraps(func)
    def decorated_function(*args, **kwargs):
        if request.method == "POST":
            token = session.get('csrf_token')
            form_token = request.form.get('csrf_token')
            
            if not token or not form_token or token != form_token:
                session.pop('csrf_token', None)
                generate_csrf_token()
                
                flash('Security validation failed. Please try again.', 'danger')
                return redirect(url_for('login'))
                
        return func(*args, **kwargs)
    return decorated_function
