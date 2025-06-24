"""Authentication service for ACME Bank."""

import logging
import os
from flask import session
from typing import Set

from database.database import Database
from services.password_service import PasswordService


class AuthService:
    """Handles user authentication and session management."""

    def __init__(self, db: Database) -> None:
        self.db = db
        self.public_routes: Set[str] = {'login', 'index', 'static'}
        self.password_service = PasswordService()
        self._setup_logger()

    def _setup_logger(self) -> None:
        """Configure authentication logging."""
        self.logger = logging.getLogger('auth_service')
        self.logger.setLevel(logging.DEBUG)
        
        os.makedirs('logs', exist_ok=True)
        handler = logging.FileHandler('logs/auth.log')
        handler.setFormatter(
            logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        )
        self.logger.addHandler(handler)

    def login(self, username: str, password: str) -> bool:
        """Authenticate user credentials."""
        try:
            query = "SELECT id, username, password FROM users WHERE username = ?"
            result = self.db.execute_query(query, (username,))
            
            if result and self.password_service.verify_password(password, result[0][2]):
                session['user_id'] = result[0][0]
                session['username'] = result[0][1]
                return True
            return False
        except Exception as e:
            self.logger.error(f"Login failed: {e}")
            return False

    def logout(self) -> None:
        """Clear user session data."""
        try:
            username = session.get('username')
            session.clear()
            self.logger.info(f"Logout successful: {username}")
        except Exception as e:
            self.logger.error(f"Logout failed: {e}")

    def is_authenticated(self) -> bool:
        """Check user authentication status."""
        return 'user_id' in session

    def is_route_public(self, endpoint: str) -> bool:
        """Check if route is publicly accessible."""
        return endpoint in self.public_routes
