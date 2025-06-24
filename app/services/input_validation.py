"""Input validation service for ACME Bank."""

from datetime import datetime
from decimal import Decimal, InvalidOperation
import html
import json
import logging
import re
from typing import Any, Dict, Union


class InputValidationError(Exception):
    """Custom validation error."""
    pass


class InputValidator:
    """Validates and sanitises user inputs."""

    def __init__(self) -> None:
        self._setup_logger()
        self._compile_regex_patterns()
        self._setup_validation_limits()

    def _setup_logger(self) -> None:
        """Initialise validation logging."""
        self.logger = logging.getLogger('input_validation')
        self.logger.setLevel(logging.INFO)
        handler = logging.FileHandler('logs/validation.log')
        handler.setFormatter(
            logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        )
        self.logger.addHandler(handler)

    def _compile_regex_patterns(self) -> None:
        """Set validation patterns."""
        self.patterns = {
            'email': re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'),
            'username': re.compile(r'^[a-zA-Z0-9_-]{3,32}$'),
            'password': re.compile(r'^(?=.*[A-Za-z])(?=.*\d)(?=.*[@$!%*#?&])[A-Za-z\d@$!%*#?&]{8,}$'),
            'name': re.compile(r'^[a-zA-Z\s-]{2,50}$'),
            'amount': re.compile(r'^\d+(\.\d{1,2})?$'),
            'account_number': re.compile(r'^\d{8,12}$'),
            'date': re.compile(r'^\d{4}-\d{2}-\d{2}$'),
            'filename': re.compile(r'^user_\d+_bank_statement\.csv$')
        }

    def _setup_validation_limits(self) -> None:
        """Set validation limits."""
        self.limits = {
            'min_amount': Decimal('0.01'),
            'max_amount': Decimal('1000000.00'),
            'max_description_length': 500,
            'max_reference_length': 50,
            'max_attempts': 5,
            'max_json_depth': 10
        }

    def sanitise_input(self, value: str) -> str:
        """Clean and sanitise input string."""
        if not isinstance(value, str):
            return str(value)
        
        value = html.escape(value)
        value = value.replace('\0', '')
        value = ''.join(c for c in value if ord(c) >= 32)
        value = re.sub(r'<script.*?>.*?</script>', '', value, flags=re.I|re.S)
        
        return value.strip()

    def is_valid_filename(self, filename: str) -> bool:
        """Validate statement filename."""
        return bool(self.patterns['filename'].match(filename))

    def validate_login_input(self, username: str, password: str) -> bool:
        """Validate login credentials."""
        try:
            if not username or not password:
                return False

            username = self.sanitise_input(username)
            return (self.patterns['username'].match(username) and 
                   self.patterns['password'].match(password))
        except Exception as e:
            self.logger.error(f"Login validation error: {e}")
            return False

    def validate_transfer_input(self, from_account: str, to_account: str, 
                              amount: Union[str, float, Decimal]) -> bool:
        """Validate transfer details."""
        try:
            if not (self.patterns['account_number'].match(str(from_account)) and 
                   self.patterns['account_number'].match(str(to_account))):
                return False

            try:
                amount = Decimal(str(amount))
            except InvalidOperation:
                return False

            if from_account == to_account:
                return False

            return self.limits['min_amount'] <= amount <= self.limits['max_amount']
        except Exception as e:
            self.logger.error(f"Transfer validation error: {e}")
            return False

    def validate_user_input(self, user_data: Dict[str, Any]) -> Dict[str, Any]:
        """Validate user data."""
        try:
            validated_data = {}
            
            for field, pattern_name in {
                'username': 'username',
                'email': 'email',
                'password': 'password',
                'firstname': 'name',
                'lastname': 'name'
            }.items():
                if field in user_data:
                    value = self.sanitise_input(user_data[field])
                    if field == 'email':
                        value = value.lower()
                    if not self.patterns[pattern_name].match(value):
                        raise InputValidationError(f"Invalid {field} format")
                    validated_data[field] = value

            return validated_data
        except Exception as e:
            self.logger.error(f"User data validation error: {e}")
            raise InputValidationError(str(e))

    def validate_payment_input(self, payment_data: Dict[str, Any]) -> Dict[str, Any]:
        """Validate payment data."""
        try:
            validated_data = {}
            
            if 'amount' in payment_data:
                try:
                    amount = Decimal(str(payment_data['amount']))
                    if not (self.limits['min_amount'] <= amount <= self.limits['max_amount']):
                        raise InputValidationError("Invalid amount")
                    validated_data['amount'] = amount
                except InvalidOperation:
                    raise InputValidationError("Invalid amount format")

            if 'reference' in payment_data:
                reference = self.sanitise_input(payment_data['reference'])
                if len(reference) > self.limits['max_reference_length']:
                    raise InputValidationError("Reference too long")
                validated_data['reference'] = reference

            if 'recipient_email' in payment_data:
                email = self.sanitise_input(payment_data['recipient_email'].lower())
                if not self.patterns['email'].match(email):
                    raise InputValidationError("Invalid recipient email")
                validated_data['recipient_email'] = email

            return validated_data
        except Exception as e:
            self.logger.error(f"Payment validation error: {e}")
            raise InputValidationError(str(e))

    def validate_json_input(self, json_string: str) -> Dict:
        """Validate JSON data."""
        try:
            data = json.loads(json_string)
            
            def check_depth(obj: Any, depth: int = 0) -> int:
                if depth > self.limits['max_json_depth']:
                    raise InputValidationError("JSON nested too deeply")
                if isinstance(obj, dict):
                    return max(check_depth(v, depth + 1) for v in obj.values())
                if isinstance(obj, list):
                    return max(check_depth(v, depth + 1) for v in obj)
                return depth

            check_depth(data)
            return data
        except json.JSONDecodeError:
            raise InputValidationError("Invalid JSON format")
        except Exception as e:
            self.logger.error(f"JSON validation error: {e}")
            raise InputValidationError(str(e))

    def validate_date_input(self, date_str: str) -> datetime:
        """Validate date string."""
        try:
            if not self.patterns['date'].match(date_str):
                raise InputValidationError("Invalid date format")
            return datetime.strptime(date_str, '%Y-%m-%d')
        except ValueError:
            raise InputValidationError("Invalid date")

    def validate_search_input(self, search_query: str) -> str:
        """Validate search query."""
        try:
            search_query = self.sanitise_input(search_query)
            if len(search_query) < 2:
                raise InputValidationError("Search query too short")
            if len(search_query) > 100:
                raise InputValidationError("Search query too long")
            return search_query
        except Exception as e:
            self.logger.error(f"Search validation error: {e}")
            raise InputValidationError(str(e))
