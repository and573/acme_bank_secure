"""Service for handling banking transactions."""

from decimal import Decimal
import uuid
from typing import List, Tuple, Optional

from database.database import Database


class TransactionService:
    """Handles all banking transaction operations."""

    def __init__(self, db: Database) -> None:
        self.db = db

    def get_statement(self, user_id: int) -> List[Tuple]:
        """Fetch user's transaction statement."""
        query = '''
            SELECT * FROM vw_account_summary
            WHERE user_id = ?
            ORDER BY Date DESC
        '''
        try:
            return self.db.execute_query(query, (user_id,))
        except Exception:
            return []

    def process_transfer(self, user_id: int, from_account: int, 
                        to_account: int, amount: float) -> bool:
        """Process internal account transfer."""
        try:
            reference = str(uuid.uuid4())

            with self.db.transaction() as cursor:
                cursor.execute("""
                    INSERT INTO transactions 
                    (user_id, from_account, to_account, transaction_type, 
                     transaction_reference, amount)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (user_id, from_account, to_account, 'TRANSFER', 
                     reference, amount))

                cursor.execute("""
                    UPDATE accounts
                    SET balance = COALESCE(
                        (SELECT SUM(amount) FROM transactions WHERE to_account = accounts.id), 0
                    ) + COALESCE(
                        (SELECT SUM(-amount) FROM transactions WHERE from_account = accounts.id), 0
                    )
                    WHERE id IN(?, ?)
                """, (from_account, to_account))

            return True
            
        except Exception:
            return False

    def transfer_funds(self, user_id: int, from_account: int, to_account: int, 
                      transaction_type: str, amount: Decimal, 
                      reference: Optional[str] = None) -> bool:
        """Process a fund transfer between accounts."""
        try:
            queries = [
                """
                UPDATE accounts 
                SET balance = balance - ? 
                WHERE id = ? AND balance >= ?
                """,
                
                """
                UPDATE accounts 
                SET balance = balance + ? 
                WHERE id = ?
                """,
                
                """
                INSERT INTO transactions 
                (user_id, from_account, to_account, transaction_type, amount, transaction_reference)
                VALUES (?, ?, ?, ?, ?, ?)
                """
            ]
            
            params_list = [
                (amount, from_account, amount),
                (amount, to_account),
                (user_id, from_account, to_account, transaction_type, amount, reference)
            ]

            return self.db.execute_transaction(queries, params_list)
                
        except Exception:
            return False
