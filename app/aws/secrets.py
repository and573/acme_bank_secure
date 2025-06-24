"""AWS Secrets Manager client for ACME Bank."""

import base64
import json
import logging
import os
from typing import Any, Dict, Optional

from botocore.exceptions import ClientError
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


class SecretsClient:
    """Manages application secrets with AWS Secrets Manager and local cache."""

    def __init__(self, region_name: str = 'us-east-1') -> None:
        self.region_name = region_name
        self._cache: Dict[str, Any] = {}
        self.local_secrets_path = os.path.join(
            os.path.dirname(__file__), 
            'secure', 
            '.secrets'
        )
        
        self._setup_logging()
        self._init_encryption()
        self._load_local_secrets()

    def _setup_logging(self) -> None:
        """Initialise secure logging configuration."""
        self.logger = logging.getLogger('secrets_manager')
        self.logger.setLevel(logging.INFO)
        
        os.makedirs('logs', exist_ok=True)
        handler = logging.FileHandler('logs/secrets.log')
        handler.setFormatter(
            logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        )
        self.logger.addHandler(handler)

    def _init_encryption(self) -> None:
        """Initialise local encryption using Fernet."""
        try:
            key_bytes = base64.b64decode(os.getenv('SECRET_KEY', ''))
            if not key_bytes:
                kdf = PBKDF2HMAC(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=b'static_salt',
                    iterations=100000,
                )
                key_bytes = kdf.derive(b"development-key")
            
            self.fernet = Fernet(base64.urlsafe_b64encode(key_bytes))
        except Exception as e:
            self.logger.error(f"Encryption setup failed: {e}")
            raise

    def _load_local_secrets(self) -> None:
        """Load secrets from local cache."""
        try:
            if os.path.exists(self.local_secrets_path):
                with open(self.local_secrets_path, 'rb') as f:
                    self._cache = json.loads(
                        self.fernet.decrypt(f.read())
                    )
        except Exception as e:
            self.logger.error(f"Cache load failed: {e}")
            self._cache = {}

    def _save_local_secrets(self) -> None:
        """Save secrets to local encrypted cache."""
        try:
            os.makedirs(os.path.dirname(self.local_secrets_path), exist_ok=True)
            with open(self.local_secrets_path, 'wb') as f:
                f.write(
                    self.fernet.encrypt(json.dumps(self._cache).encode())
                )
        except Exception as e:
            self.logger.error(f"Cache save failed: {e}")
            raise

    def get_secret(self, secret_name: str, force_refresh: bool = False) -> Optional[Dict[str, Any]]:
        """Retrieve secret from AWS or cache."""
        try:
            if not force_refresh and secret_name in self._cache:
                return self._cache[secret_name]

            response = self.client.get_secret_value(SecretId=secret_name)
            
            if 'SecretString' in response:
                secret = json.loads(response['SecretString'])
                self._cache[secret_name] = secret
                self._save_local_secrets()
                return secret

            self.logger.error(f"Secret not found: {secret_name}")
            return None

        except ClientError as e:
            error_code = e.response['Error']['Code']
            self.logger.error(f"AWS error ({error_code}): {e}")
            return None
        