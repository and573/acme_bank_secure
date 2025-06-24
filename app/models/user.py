"""User model for ACME Bank."""

from datetime import datetime
import hashlib
import re
from typing import Dict


class User:
    """Bank user with validation and security features."""

    def __init__(self, id: int, username: str, email: str, firstname: str, 
                 lastname: str, password: str = None) -> None:
        self.id = id
        self._username = self._validate_username(username) and username
        self._email = self._validate_email(email) and email
        self._firstname = firstname.strip()
        self._lastname = lastname.strip()
        self._password = password
        self.created_at = datetime.now()
        self.last_login = None

    @property
    def username(self) -> str:
        return self._username

    @username.setter
    def username(self, value: str) -> None:
        if not self._validate_username(value):
            raise ValueError("Invalid username format")
        self._username = value

    @property
    def email(self) -> str:
        return self._email

    @email.setter
    def email(self, value: str) -> None:
        if not self._validate_email(value):
            raise ValueError("Invalid email format")
        self._email = value

    @property
    def firstname(self) -> str:
        return self._firstname

    @firstname.setter
    def firstname(self, value: str) -> None:
        if not value or not value.strip():
            raise ValueError("First name cannot be empty")
        self._firstname = value.strip()

    @property
    def lastname(self) -> str:
        return self._lastname

    @lastname.setter
    def lastname(self, value: str) -> None:
        if not value or not value.strip():
            raise ValueError("Last name cannot be empty")
        self._lastname = value.strip()

    @staticmethod
    def _validate_username(username: str) -> bool:
        """Validate username format."""
        if not username or len(username) < 3 or len(username) > 30:
            return False
        return bool(re.match(r'^[a-zA-Z0-9_-]+$', username))

    @staticmethod
    def _validate_email(email: str) -> bool:
        """Validate email format."""
        email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return bool(re.match(email_regex, email))

    def set_password(self, password: str) -> None:
        """Set hashed password."""
        if not password or len(password) < 8:
            raise ValueError("Password must be at least 8 characters")
        self._password = hashlib.sha256(password.encode()).hexdigest()

    def check_password(self, password: str) -> bool:
        """Verify password hash."""
        if not self._password:
            return False
        return self._password == hashlib.sha256(password.encode()).hexdigest()

    def update_last_login(self) -> None:
        """Update last login timestamp."""
        self.last_login = datetime.now()

    def to_dict(self) -> Dict:
        """Convert user to dictionary."""
        return {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'firstname': self.firstname,
            'lastname': self.lastname,
            'created_at': self.created_at.isoformat(),
            'last_login': self.last_login.isoformat() if self.last_login else None
        }

    @classmethod
    def from_dict(cls, data: Dict) -> 'User':
        """Create user from dictionary."""
        user = cls(
            id=data.get('id'),
            username=data.get('username'),
            email=data.get('email'),
            firstname=data.get('firstname'),
            lastname=data.get('lastname')
        )
        if 'password' in data:
            user.set_password(data['password'])
        return user
