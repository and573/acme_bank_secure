"""Database management system for ACME Bank."""

import logging
import os
import sqlite3
import threading
from queue import Queue
from sqlite3 import Connection, Cursor
from typing import List, Optional, Tuple
from contextlib import contextmanager


class DatabaseError(Exception):
    """Custom database exception."""
    pass


class DatabaseConnectionPool:
    """Manages SQLite database connections."""
    
    def __init__(self, db_path: str = 'instance/acme_bank.db', max_connections: int = 5):
        self.db_path = db_path
        self.max_connections = max_connections
        self.connections: Queue = Queue(maxsize=max_connections)
        self.lock = threading.Lock()
        self._initialize_pool()

    def _initialize_pool(self) -> None:
        """Create initial connection pool."""
        for _ in range(self.max_connections):
            conn = self._create_connection()
            self.connections.put(conn)

    def _create_connection(self) -> Connection:
        """Create new database connection with safety settings."""
        conn = sqlite3.connect(
            self.db_path,
            check_same_thread=False,
            timeout=30.0,
            isolation_level='EXCLUSIVE'
        )
        conn.execute('PRAGMA foreign_keys = ON')
        conn.execute('PRAGMA secure_delete = ON')
        return conn

    def get_connection(self) -> Connection:
        """Get connection from pool."""
        try:
            return self.connections.get(timeout=30)
        except Exception as e:
            logging.error(f"Connection error: {e}")
            raise DatabaseError("Cannot get database connection")

    def return_connection(self, conn: Connection) -> None:
        """Return connection to pool."""
        try:
            self.connections.put(conn)
        except Exception as e:
            logging.error(f"Connection return error: {e}")
            conn.close()

    def close_all(self) -> None:
        """Close all pool connections."""
        while not self.connections.empty():
            conn = self.connections.get()
            conn.close()


class Database:
    """Main database management class."""

    def __init__(self, db_path: str = 'instance/bank.db'):
        self.db_path = db_path
        self.logger = self._setup_logger()
        self._validate_db_path()
        self.pool = DatabaseConnectionPool(db_path)

    def _setup_logger(self) -> logging.Logger:
        """Set up database logging."""
        os.makedirs('logs', exist_ok=True)
        logger = logging.getLogger('database')
        logger.setLevel(logging.INFO)
        handler = logging.FileHandler('logs/database.log')
        handler.setFormatter(
            logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        )
        logger.addHandler(handler)
        return logger

    def _validate_db_path(self) -> None:
        """Validate database path and initialise if needed."""
        try:
            os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
            if not os.path.exists(self.db_path):
                self._init_database()
            with open(self.db_path, 'a'):
                pass
        except Exception as e:
            self.logger.error(f"Database init error: {e}")
            raise DatabaseError(f"Database initialisation failed: {e}")

    def _init_database(self) -> None:
        """Create database schema."""
        try:
            schema_path = os.path.join(
                os.path.dirname(os.path.abspath(__file__)), 
                'database.sql'
            )
            with open(schema_path, 'r') as f:
                schema = f.read()
            
            conn = sqlite3.connect(self.db_path)
            try:
                conn.executescript(schema)
                conn.commit()
                self.logger.info("Database initialised")
            finally:
                conn.close()
        except Exception as e:
            self.logger.error(f"Schema creation failed: {e}")
            raise DatabaseError(f"Schema creation failed: {e}")

    @contextmanager
    def get_cursor(self) -> Cursor:
        """Get database cursor with automatic connection management."""
        conn = self.pool.get_connection()
        try:
            cursor = conn.cursor()
            yield cursor
            conn.commit()
        except Exception as e:
            conn.rollback()
            self.logger.error(f"Database error: {e}")
            raise DatabaseError(f"Operation failed: {e}")
        finally:
            cursor.close()
            self.pool.return_connection(conn)

    def execute_query(self, query: str, params: tuple = ()) -> Optional[List[Tuple]]:
        """Execute parameterised SQL query."""
        try:
            with self.get_cursor() as cursor:
                cursor.execute(query, params)
                return cursor.fetchall()
        except Exception as e:
            self.logger.error(f"Query error: {str(e)[:100]}")
            raise DatabaseError("Database operation failed")

    def execute_many(self, query: str, params_list: List[tuple]) -> None:
        """Execute batch SQL query."""
        try:
            with self.get_cursor() as cursor:
                cursor.executemany(query, params_list)
        except Exception as e:
            self.logger.error(f"Batch query failed: {e}")
            raise DatabaseError(f"Batch operation failed: {e}")

    @contextmanager
    def transaction(self):
        """Handle database transactions with automatic connection management."""
        conn = self.pool.get_connection()
        try:
            cursor = conn.cursor()
            yield cursor
            conn.commit()
        except Exception as e:
            conn.rollback()
            self.logger.error(f"Transaction failed: {e}")
            raise DatabaseError(f"Transaction failed: {e}")
        finally:
            self.pool.return_connection(conn)

    def execute_transaction(self, queries: List[str], params_list: List[tuple]) -> bool:
        """Execute multiple queries in a single transaction."""
        with self.transaction() as cursor:
            for query, params in zip(queries, params_list):
                cursor.execute(query, params)
            return True

    def __del__(self):
        """Clean up database connections."""
        if hasattr(self, 'pool'):
            try:
                self.pool.close_all()
            except Exception as e:
                if hasattr(self, 'logger'):
                    self.logger.error(f"Cleanup failed: {e}")
