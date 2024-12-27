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
            password TEXT NOT NULL,
            salt TEXT NOT NULL
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

    def add_password(self, site, username, password, salt):
        query = """INSERT INTO passwords (site, username, password, salt) VALUES (?, ?, ?, ?)"""
        self.conn.execute(query, (site, username, password, salt))
        self.conn.commit()

    def get_password(self, site):
        query = """SELECT username, password, salt FROM passwords WHERE site = ?"""
        cursor = self.conn.execute(query, (site,))
        results = cursor.fetchall()
        if results:
            return [
                {"username": username, "password": password, "salt": salt}
                for username, password, salt in results
            ]
        return None
    

    def delete_password(self, site, username):
        query = "DELETE FROM passwords WHERE site = ? AND username = ?"
        self.conn.execute(query, (site, username))
        self.conn.commit()

    def list_all_passwords(self):
        query = """SELECT site, username, password, salt FROM passwords"""
        cursor = self.conn.execute(query)
        return cursor.fetchall()

    def store_master_password(self, hashed_password):
        query = """INSERT INTO settings (key, value) VALUES ('master_password', ?)"""
        self.conn.execute(query, (hashed_password, ))
        self.conn.commit()

    def get_stored_master_password(self):
        query = """SELECT value FROM settings WHERE key = 'master_password'"""
        cursor = self.conn.execute(query)
        result = cursor.fetchone()
        if result:
            return result[0]
        return None
