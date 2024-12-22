import sqlite3

class Database:
    def __init__(self, db_name):
        self.conn = sqlite3.connect(db_name)
        self.create_table()

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

    def add_password(self, site, username, password):
        query = "INSERT INTO passwords (site, username, password) VALUES (?, ?, ?)"
        self.conn.execute(query, (site, username, password))
        self.conn.commit()

    def get_password(self, site):
        query = "SELECT username, password FROM passwords WHERE site = ?"
        cursor = self.conn.execute(query, (site,))
        return cursor.fetchone()

    def delete_password(self, site):
        query = "DELETE FROM passwords WHERE site = ?"
        self.conn.execute(query, (site,))
        self.conn.commit()
