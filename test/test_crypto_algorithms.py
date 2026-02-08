import unittest

from algorithms import AESalgorithm, RSAalgorithm, generateKey, hashalg


class CryptoAlgorithmsTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.private_key, cls.public_key = generateKey.generateMyKey("keys/test/test")

    def test_aes_encrypt_decrypt_roundtrip_text(self):
        key = AESalgorithm.genKey()
        plaintext = "工业级重构验证"
        encrypted = AESalgorithm.AesEncrypt(plaintext, key)
        decrypted = AESalgorithm.AesDecrypt(encrypted, key)
        self.assertEqual(decrypted.decode("utf-8"), plaintext)

    def test_aes_encrypt_decrypt_roundtrip_bytes(self):
        key = AESalgorithm.genKey()
        payload = b"\x00\x01binary-data\xfe"
        encrypted = AESalgorithm.AesEncrypt(payload, key)
        decrypted = AESalgorithm.AesDecrypt(encrypted, key)
        self.assertEqual(decrypted, payload)

    def test_rsa_encrypt_decrypt_roundtrip(self):
        data = b"one-time-key"
        encrypted = RSAalgorithm.RsaEncrypt(data, self.public_key)
        decrypted = RSAalgorithm.RsaDecrypt(encrypted, self.private_key)
        self.assertEqual(decrypted, data)

    def test_rsa_sign_verify(self):
        message = "signed-message"
        signature = RSAalgorithm.RsaSignal(message, self.private_key)
        self.assertTrue(RSAalgorithm.VerRsaSignal(message, signature, self.public_key))

    def test_hash_sha256(self):
        digest = hashalg.hash_sha256("abc")
        self.assertEqual(digest, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")


if __name__ == "__main__":
    unittest.main()
