import sqlite3


class Database:
    def __init__(self, db_name):
        self.conn = sqlite3.connect(db_name)
        self.create_table()
        self.create_settings_table()

    def create_table(self):
        query = """
        CREATE TABLE IF NOT EXISTS passwords (
            id INTEGER PRIMARY KEY,
            site TEXT NOT NULL,
            username TEXT NOT NULL,
            password TEXT NOT NULL
        )
        """
        self.conn.execute(query)
        self.conn.commit()

    def create_settings_table(self):
        query = """
        CREATE TABLE IF NOT EXISTS settings (
            id INTEGER PRIMARY KEY,
            key TEXT UNIQUE NOT NULL,
            value TEXT NOT NULL
        )
        """
        self.conn.execute(query)
        self.conn.commit()

    def add_password(self, site, username, password):
        query = "INSERT INTO passwords (site, username, password) VALUES (?, ?, ?)"
        self.conn.execute(query, (site, username, password))
        self.conn.commit()

    def get_password(self, site):
        query = "SELECT username, password FROM passwords WHERE site = ?"
        cursor = self.conn.execute(query, (site,))
        result = cursor.fetchall()
        if result:
            return result
        return None

    def delete_password(self, site):
        query = "DELETE FROM passwords WHERE site = ?"
        self.conn.execute(query, (site,))
        self.conn.commit()

    def list_all_passwords(self):
        query = "SELECT site, username, password FROM passwords"
        cursor = self.conn.execute(query)
        return cursor.fetchall()

    def store_master_password(self, hashed_password):
        query = """
        INSERT INTO settings (key, value) VALUES ('master_password', ?)
        """
        self.conn.execute(query, (hashed_password, ))
        self.conn.commit()

    def get_stored_master_password(self):
        query = """
        SELECT value FROM settings WHERE key = 'master_password'
        """
        cursor = self.conn.execute(query)
        result = cursor.fetchone()
        if result:
            return result[0]
        return None
