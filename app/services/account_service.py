"""Service for handling bank account operations."""

from typing import List, Tuple, Optional
from database.database import Database


class AccountService:
    """Manages bank account operations."""

    def __init__(self, db: Database):
        self.db = db

    def get_user_accounts(self, user_id: int) -> List[Tuple]:
        """Fetch all accounts for a user."""
        query = '''
            SELECT at.name, acc.balance
            FROM accounts acc
            INNER JOIN account_types at on at.id=acc.account_type 
            WHERE acc.user_id = ?
        '''
        return self.db.execute_query(query, (user_id,))

    def get_account_types(self) -> List[Tuple]:
        """Fetch available account types."""
        query = 'SELECT id, name FROM account_types WHERE id!=0'
        return self.db.execute_query(query)

    def get_account_for_user(self, user_id: int, account_type: int) -> Optional[Tuple]:
        """Get account details for a specific user and account type."""
        query = """
            SELECT a.id, a.user_id, a.account_type, a.balance
            FROM accounts a
            WHERE a.user_id = ? AND a.account_type = ?
        """
        result = self.db.execute_query(query, (user_id, account_type))
        return result[0] if result else None

    def get_account_for_email(self, email: str) -> Optional[Tuple]:
        """Get account details for a user by email."""
        query = """
            SELECT a.id, a.user_id, a.account_type, a.balance
            FROM accounts a
            JOIN users u ON a.user_id = u.id
            WHERE u.email = ? AND a.account_type = 1
        """
        result = self.db.execute_query(query, (email,))
        return result[0] if result else None
