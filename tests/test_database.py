import unittest
from database.database import Database
import os


class TestDatabase(unittest.TestCase):
    def setUp(self):
        self.db = Database("database/test_passwords.db")

    def test_add_password(self):
        self.db.add_password("example.com", "user1", "password123")
        result = self.db.get_password("example.com")

        self.assertIsNotNone(result)
        self.assertEqual(result[0][0], "user1")
        self.assertEqual(result[0][1], "password123")

    def test_delete_password(self):
        self.db.add_password("example.com", "user1", "password123")
        self.db.delete_password("example.com")

        result = self.db.get_password("example.com")
        self.assertIsNone(result)

    def tearDown(self):
        os.remove("database/test_passwords.db")


if __name__ == "__main__":
    unittest.main()
