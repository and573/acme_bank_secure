"""Transaction model for ACME Bank."""

from datetime import datetime
from decimal import Decimal, InvalidOperation
import uuid
from typing import Dict, Set


class Transaction:
    """Handles bank transaction operations."""

    VALID_TYPES: Set[str] = {'DEPOSIT', 'TRANSFER', 'PAYMENT'}

    def __init__(self, id: int, user_id: int, from_account: int, 
                 to_account: int, transaction_type: str, amount: Decimal, 
                 reference: str = None) -> None:
        self.id = id
        self.user_id = user_id
        self.from_account = from_account
        self.to_account = to_account
        self._transaction_type = self._validate_transaction_type(transaction_type)
        self._amount = self._validate_amount(amount)
        self.transaction_reference = reference or str(uuid.uuid4())
        self.transaction_timestamp = datetime.now()
        self.status = 'PENDING'

    @property
    def transaction_type(self) -> str:
        return self._transaction_type

    @transaction_type.setter
    def transaction_type(self, value: str) -> None:
        self._transaction_type = self._validate_transaction_type(value)

    @property
    def amount(self) -> Decimal:
        return self._amount

    @amount.setter
    def amount(self, value: Decimal) -> None:
        self._amount = self._validate_amount(value)

    @staticmethod
    def _validate_transaction_type(transaction_type: str) -> str:
        """Validate transaction type."""
        if transaction_type not in Transaction.VALID_TYPES:
            raise ValueError(f"Invalid transaction type: {transaction_type}")
        return transaction_type

    @staticmethod
    def _validate_amount(amount: Decimal) -> Decimal:
        """Validate transaction amount."""
        try:
            amount = Decimal(str(amount))
            if amount <= 0:
                raise ValueError("Amount must be positive")
            return amount.quantize(Decimal('.01'))
        except InvalidOperation:
            raise ValueError("Invalid amount format")

    def complete(self) -> None:
        """Mark transaction as completed."""
        self.status = 'COMPLETED'

    def fail(self) -> None:
        """Mark transaction as failed."""
        self.status = 'FAILED'

    def to_dict(self) -> Dict:
        """Convert transaction to dictionary."""
        return {
            'id': self.id,
            'user_id': self.user_id,
            'from_account': self.from_account,
            'to_account': self.to_account,
            'transaction_type': self.transaction_type,
            'amount': str(self.amount),
            'reference': self.transaction_reference,
            'timestamp': self.transaction_timestamp.isoformat(),
            'status': self.status
        }

    @classmethod
    def from_dict(cls, data: Dict) -> 'Transaction':
        """Create transaction from dictionary."""
        return cls(
            id=data.get('id'),
            user_id=data.get('user_id'),
            from_account=data.get('from_account'),
            to_account=data.get('to_account'),
            transaction_type=data.get('transaction_type'),
            amount=Decimal(str(data.get('amount', '0.00'))),
            reference=data.get('reference')
        )

    def validate_transaction(self) -> bool:
        """Validate transaction details."""
        if self.transaction_type == 'TRANSFER':
            return self.from_account != self.to_account
        return True
