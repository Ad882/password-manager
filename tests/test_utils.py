import unittest
from utils import generate_password


class TestUtils(unittest.TestCase):
    def test_generate_password(self):
        password = generate_password(16)

        self.assertEqual(len(password), 16)
        self.assertTrue(any(c.isdigit() for c in password))
        self.assertTrue(any(c.isalpha() for c in password))


if __name__ == "__main__":
    unittest.main()
