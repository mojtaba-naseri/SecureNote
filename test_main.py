import unittest
import os
import main
from PIL import Image

class TestMain(unittest.TestCase):

    def setUp(self):
        # Create a dummy file for testing
        self.test_file_name = "test_file.txt"
        with open(self.test_file_name, "w") as f:
            f.write("This is a test file for encryption and decryption.")
            f.write("It has multiple lines.\n")
            f.write("And some more content.\n")
            f.write("And even more.\n")
            f.write("And more.\n")
            f.write("And more.\n")
            f.write("And more.\n")
            f.write("And more.\n")


    def tearDown(self):
        # Clean up the dummy files
        files_to_remove = [
            self.test_file_name,
            "test_file.txt-encrypted",
            "test_file.txt-decrypted",
            "0.text",
            "1.text",
            "decrypted_file",
            "0.text-encrypted-encoded-base64.png",
            "1.text-encrypted-encoded-base64.png",
            "0.text-encrypted",
            "1.text-encrypted",
            "0.text-encrypted-encoded-base64",
            "1.text-encrypted-encoded-base64",
            "0.text-encrypted-decoded-base64",
            "1.text-encrypted-decoded-base64",
            "0.text-decrypted-decoded-base64",
            "1.text-decrypted-decoded-base64",
        ]
        for f in files_to_remove:
            if os.path.exists(f):
                os.remove(f)

    def test_derive_key_and_iv(self):
        password = "test_password"
        salt = b'1234567890123456'
        key_length = 32
        iv_length = 16
        key, iv = main.derive_key_and_iv(password, salt, key_length, iv_length)
        self.assertEqual(len(key), key_length)
        self.assertEqual(len(iv), iv_length)

    def test_encryption_decryption(self):
        password = "test_password"
        with open(self.test_file_name, 'rb') as in_file, open('test_file.txt-encrypted', 'wb') as out_file:
            main.encrypt(in_file, out_file, password)

        with open('test_file.txt-encrypted', 'rb') as in_file, open('test_file.txt-decrypted', 'wb') as out_file:
            main.decrypt(in_file, out_file, password)

        with open(self.test_file_name, 'r') as f1, open('test_file.txt-decrypted', 'r') as f2:
            self.assertEqual(f1.read(), f2.read())

    def test_spliter_concatenation(self):
        main.spliter(self.test_file_name)
        self.assertTrue(os.path.exists("0.text"))
        self.assertTrue(os.path.exists("1.text"))

        # create dummy decrypted files to test concatenation
        with open("0.text-decrypted-decoded-base64", "w") as f:
            f.write("This is a test file for encryption and decryption.")
            f.write("It has multiple lines.\n")
            f.write("And some more content.\n")
            f.write("And even more.\n")

        with open("1.text-decrypted-decoded-base64", "w") as f:
            f.write("And more.\n")
            f.write("And more.\n")
            f.write("And more.\n")
            f.write("And more.\n")


        main.concatenation()
        self.assertTrue(os.path.exists("decrypted_file"))

        with open(self.test_file_name, 'r') as f1, open('decrypted_file', 'r') as f2:
            self.assertEqual(f1.read(), f2.read())


    def test_qrcode_generator_and_convertor(self):
        test_data = "test_qrcode_data"
        test_file = "test_qrcode.txt"
        with open(test_file, "w") as f:
            f.write(test_data)

        main.qrcode_generator(test_file)
        self.assertTrue(os.path.exists("test_qrcode.txt.png"))

        converted_data = main.qrcode_convertor("test_qrcode.txt.png")
        self.assertEqual(test_data, converted_data)

        os.remove("test_qrcode.txt.png")

if __name__ == '__main__':
    unittest.main()
