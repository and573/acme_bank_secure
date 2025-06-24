"""Password management service for ACME Bank."""

import bcrypt
from typing import Optional


class PasswordService:
    """Handles password hashing and verification."""
    
    def hash_password(self, password: str) -> str:
        """Create secure hash of password."""
        if not password:
            raise ValueError("Password cannot be empty")
            
        try:
            salt = bcrypt.gensalt()
            return bcrypt.hashpw(password.encode(), salt).decode()
        except Exception as e:
            raise RuntimeError(f"Password hashing failed: {e}")

    def verify_password(self, password: str, hashed: str) -> bool:
        """Check if password matches hash."""
        if not password or not hashed:
            return False
            
        try:
            return bcrypt.checkpw(password.encode(), hashed.encode())
        except Exception:
            return False
