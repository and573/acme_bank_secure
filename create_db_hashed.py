"""
Database initialiser for ACME Bank Database.

Execute to setup the database with password hashes.

This script does not run as part of the main program. 
"""


import os
import sqlite3
import bcrypt
from typing import List, Tuple


class PasswordService:
    """Password hashing service."""
    
    def hash_password(self, password: str) -> str:
        """Hash password using bcrypt."""
        salt = bcrypt.gensalt()
        hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
        return hashed.decode('utf-8')


def init_database() -> None:
    """Initialise bank database with schema and default data."""
    
    password_service = PasswordService()
    
    users = [
        (0, 'SYSTEM', 'P4$$w0rd', 'SYSTEM', 'SYSTEM', ''),
        (1, 'admin', 'P4$$w0rd', 'admin', 'admin', 'admin@gloscol.ac.uk'),
        (2, 'fred', 'fred', 'Fred', 'Bloggs', 'fred@gloscol.ac.uk'),
        (3, 'amy', 'amy', 'Amy', 'Anderson', 'amy@gloscol.ac.uk'),
        (4, 'badactor', 'badactor', 'bad', 'actor', 'malicious@badactors.com')
    ]
    
    users_with_hashed_passwords = [
        (id, username, password_service.hash_password(password), firstname, lastname, email)
        for id, username, password, firstname, lastname, email in users
    ]
    
    if os.path.exists('bank.db'):
        os.remove('bank.db')

    try:
        conn = sqlite3.connect('bank.db')
        cursor = conn.cursor()
        
        cursor.execute('PRAGMA foreign_keys = ON;')
        
        cursor.execute('''
        CREATE TABLE account_types (
            id INTEGER PRIMARY KEY,
            name TEXT NOT NULL UNIQUE
        );
        ''')
        
        cursor.execute('''
        INSERT INTO account_types (id, name) VALUES
            (0, 'Cash'),
            (1, 'Current'),
            (2, 'Savings');
        ''')
        
        cursor.execute('''
        CREATE TABLE users (
            id INTEGER PRIMARY KEY,
            username TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL,
            firstname TEXT,
            lastname TEXT,
            email TEXT
        );
        ''')
        
        cursor.executemany('''
        INSERT INTO users (id, username, password, firstname, lastname, email) 
        VALUES (?, ?, ?, ?, ?, ?);
        ''', users_with_hashed_passwords)
        
        cursor.execute('''
        CREATE TABLE accounts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            account_type INTEGER NOT NULL,
            balance REAL NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users (id),
            FOREIGN KEY (account_type) REFERENCES account_types (id)
        );
        ''')
        
        cursor.execute('''
        INSERT INTO accounts (user_id, account_type, balance) VALUES 
            (0, 0, 50000000),
            (1, 1, 0), (2, 1, 0), (3, 1, 0), (4, 1, 0),
            (1, 2, 0), (2, 2, 0), (3, 2, 0), (4, 2, 0);
        ''')
        
        cursor.execute('''
        CREATE TABLE transactions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            from_account INTEGER,
            to_account INTEGER,
            transaction_type TEXT,
            transaction_reference TEXT,
            amount REAL,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id),
            FOREIGN KEY (from_account) REFERENCES accounts (id),
            FOREIGN KEY (to_account) REFERENCES accounts (id)
        );
        ''')
        
        cursor.execute('''
        INSERT INTO transactions (user_id, from_account, to_account, transaction_type, amount)
        VALUES 
            (1, 1, 2, 'DEPOSIT', 200),
            (2, 1, 3, 'DEPOSIT', 200),
            (3, 1, 4, 'DEPOSIT', 200),
            (1, 1, 5, 'DEPOSIT', 1000),
            (2, 1, 6, 'DEPOSIT', 1000),
            (3, 1, 7, 'DEPOSIT', 1000);
        ''')
        
        cursor.execute('''
        UPDATE accounts 
        SET balance = COALESCE(
            (SELECT SUM(amount) FROM transactions WHERE transactions.to_account = accounts.id),
            0
        ) 
        WHERE id != 1;
        ''')
        
        cursor.execute('''
        CREATE VIEW vw_account_summary AS
            SELECT t.id, to_a.user_id,
                t.timestamp as 'Date',
                'Deposit' as 'Type', 
                'Cash Deposit' as 'From',
                to_at.name as 'To',
                t.amount as 'Amount',
                'Deposit' as 'Reference'
            FROM transactions AS t 
            inner join accounts as to_a ON to_a.id = t.to_account
            inner join account_types as to_at ON to_at.id = to_a.account_type
            WHERE transaction_type="DEPOSIT"
            UNION
            SELECT t.id, t.user_id,
                t.timestamp as 'Date',
                'Transfer' as 'Type', 
                from_at.name as 'From',
                to_at.name as 'To',
                t.amount as 'Amount',
                'Transfer' as 'Reference'
            FROM transactions AS t 
            inner join accounts as from_a ON from_a.id = t.from_account
            inner join account_types as from_at ON from_at.id = from_a.account_type
            inner join accounts as to_a ON to_a.id = t.to_account
            inner join account_types as to_at ON to_at.id = to_a.account_type
            WHERE transaction_type="TRANSFER"
            UNION
            SELECT t.id, t.user_id,
                t.timestamp as 'Date',
                'Pay Someone' as 'Type', 
                from_at.name as 'From',
                to_u.email as 'To',
                t.amount as 'Amount',
                transaction_reference as 'Reference'
            FROM transactions AS t 
            inner join accounts as from_a ON from_a.id = t.from_account
            inner join account_types as from_at ON from_at.id = from_a.account_type
            inner join accounts as to_a ON to_a.id = t.to_account
            inner join account_types as to_at ON to_at.id = to_a.account_type
            inner join users as to_u ON to_u.id = to_a.user_id
            WHERE transaction_type="PAYMENT"
            ORDER by timestamp;
        ''')
        
        conn.commit()
        
    except Exception as e:
        if os.path.exists('bank.db'):
            os.remove('bank.db')
        raise
    finally:
        conn.close()


if __name__ == "__main__":
    init_database()
