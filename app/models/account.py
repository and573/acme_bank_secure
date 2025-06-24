"""Account model for ACME Bank."""

from decimal import Decimal, InvalidOperation
from typing import Dict


class Account:
    """Bank account with validation and type checking."""
    
    VALID_ACCOUNT_TYPES: set = {0, 1, 2}
    ACCOUNT_TYPE_NAMES: Dict[int, str] = {
        0: 'Cash',
        1: 'Current',
        2: 'Savings'
    }

    def __init__(self, id: int, user_id: int, account_type: int, 
                 balance: Decimal = Decimal('0.00')) -> None:
        self.id = id
        self.user_id = user_id
        self._account_type = self._validate_account_type(account_type)
        self._balance = self._validate_balance(balance)

    @staticmethod
    def _validate_account_type(account_type: int) -> int:
        """Validate account type."""
        if account_type not in Account.VALID_ACCOUNT_TYPES:
            raise ValueError(f"Invalid account type: {account_type}")
        return account_type

    @staticmethod
    def _validate_balance(balance: Decimal) -> Decimal:
        """Validate and format balance."""
        try:
            return Decimal(str(balance)).quantize(Decimal('.01'))
        except InvalidOperation:
            raise ValueError("Invalid balance amount")

    @property
    def balance(self) -> Decimal:
        return self._balance

    @balance.setter
    def balance(self, value: Decimal) -> None:
        self._balance = self._validate_balance(value)

    @property
    def account_type(self) -> int:
        return self._account_type

    @account_type.setter
    def account_type(self, value: int) -> None:
        self._account_type = self._validate_account_type(value)

    @property
    def account_type_name(self) -> str:
        return self.ACCOUNT_TYPE_NAMES.get(self._account_type, 'Unknown')

    def deposit(self, amount: Decimal) -> None:
        """Process account deposit."""
        if amount <= 0:
            raise ValueError("Deposit amount must be positive")
        self.balance += Decimal(str(amount))

    def withdraw(self, amount: Decimal) -> None:
        """Process account withdrawal."""
        amount = Decimal(str(amount))
        if amount <= 0:
            raise ValueError("Withdrawal amount must be positive")
        if amount > self.balance:
            raise ValueError("Insufficient funds")
        self.balance -= amount

    def has_sufficient_funds(self, amount: Decimal) -> bool:
        """Check withdrawal possibility."""
        return self.balance >= Decimal(str(amount))

    def to_dict(self) -> dict:
        """Convert account to dictionary."""
        return {
            'id': self.id,
            'user_id': self.user_id,
            'account_type': self.account_type,
            'account_type_name': self.account_type_name,
            'balance': str(self.balance)
        }

    @classmethod
    def from_dict(cls, data: dict) -> 'Account':
        """Create account from dictionary."""
        return cls(
            id=data.get('id'),
            user_id=data.get('user_id'),
            account_type=data.get('account_type'),
            balance=Decimal(str(data.get('balance', '0.00')))
        )

    @classmethod
    def from_db_row(cls, row: tuple) -> 'Account':
        """Create account from database row."""
        return cls(
            id=row[0],
            user_id=row[1],
            account_type=row[2],
            balance=Decimal(str(row[3]))
        )
