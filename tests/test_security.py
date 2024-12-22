import unittest
from security import Security
import bcrypt


class TestSecurity(unittest.TestCase):
    def setUp(self):
        self.security = Security()
        self.master_password = "test_master_password"
        self.hash_password = bcrypt.hashpw(
            self.master_password.encode(), bcrypt.gensalt()
        )

    def test_verify_master_password_success(self):
        self.security.initialize_master_password(self.master_password)

        self.assertTrue(self.security.verify_master_password(self.master_password))

    def test_verify_master_password_fail(self):
        self.security.initialize_master_password(self.master_password)
        wrong_password = "wrong_password"

        self.assertFalse(self.security.verify_master_password(wrong_password))

    def test_encrypt_decrypt(self):
        password = "secret_password"
        encrypted = self.security.encrypt(password, self.master_password)
        decrypted = self.security.decrypt(encrypted, self.master_password)

        self.assertEqual(password, decrypted)


if __name__ == "__main__":
    unittest.main()
