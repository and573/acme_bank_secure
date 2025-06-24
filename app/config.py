"""Configuration settings for ACME Bank application."""

from aws.secrets import SecretsClient

class BaseConfig:
    """Base configuration with common settings."""
    
    # Core settings
    DEBUG = False
    DROPDB = False
    ASSET_FOLDER = 'static/statements'
    
    # Security settings
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_SAMESITE = 'Strict'
    PERMANENT_SESSION_LIFETIME = 1800  # 30 minutes
    
    # Headers
    SECURE_HEADERS = {
        'X-Frame-Options': 'DENY',
        'X-XSS-Protection': '1; mode=block',
        'X-Content-Type-Options': 'nosniff',
        'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
        'Referrer-Policy': 'strict-origin-when-cross-origin',
        'Permissions-Policy': 'geolocation=(), microphone=(), camera=()'
    }
    
    @classmethod
    def load_secrets(cls) -> None:
        """Load sensitive configurations from AWS Secrets Manager."""
        try:
            secrets_client = SecretsClient()
            secrets = secrets_client.get_secret('ACME-Web-App')
            if not secrets:
                raise ValueError("No secrets found in AWS Secrets Manager")
            
            cls.SECRET_KEY = secrets['SECRET_KEY']
            cls.DATABASE_URI = secrets['DATABASE_URI']
            cls.USERNAME = secrets['USERNAME']
            cls.PASSWORD = secrets['PASSWORD']

            # NOTE: To run without AWS Secrets Manager uncomment lines below
            # cls.SECRET_KEY = 'your_secret_key'
            # cls.DATABASE_URI = 'bank.db'
            # cls.USERNAME = 'admin'
            # cls.PASSWORD = 'P4$$w0rd'
            
        except Exception as e:
            raise RuntimeError(f"Failed to load secrets: {e}")


class DevelopmentConfig(BaseConfig):
    """Development environment configuration."""
    
    def __init__(self):
        super().load_secrets()


class TestConfig(BaseConfig):
    """Test environment configuration."""
    
    def __init__(self):
        super().load_secrets()
    
    DROPDB = True
    DEBUG = False


class ProductionConfig(BaseConfig):
    """Production environment configuration."""
    
    def __init__(self):
        super().load_secrets()
    
    DEBUG = False
