import binascii
import hashlib
from base64 import b64decode, b64encode
from Crypto.Cipher import AES
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA

class EncryptionUtils:

    def __init__(self, aes_key, account_details, bank_public_key=None):
        print('Preparing AES key')
        # convert to byte array in preparation for conversion to hexadecimal
        key_bytes = bytearray.fromhex('752EF0D8FB4958670DBA40AB1F3C1D0F8FB4958670DBA40AB1F3752EF0DC1D0F')
        print('byte array: ' + str(key_bytes))
        print('length: ' + str(key_bytes.__len__()))
        self.aes_key = bytes(key_bytes)
        self.bank_public_key = bank_public_key
        self.bank_rsa = None
        self.account_details = account_details
        self.aes = AES.new(self.aes_key, AES.MODE_ECB)

    def set_bank_public_key(self, bank_pu):
        public_modulus = 'CF9E0B601B6BD9335619470D3C22EED15D73B7D6D3AEB725FF4E458ED13D20D48027F2300A4346427E8FBB30C6F6C9E7AAC7B88AB3D376CCF5AF05E0B188CFA1F361F8B5B78C4E9EFC95A667B0AD26D5593FCAF629BB098AAFC7DF6F523D51450C9B7BF1A62EE4D3466D4D69D6B6C5E8488A6BC2BC70B09ED96753BA248516B3'
        public_exponent = '0x10001'
        # convert to byte array in preparation for conversion to hexadecimal

        public_mod_int = int(public_modulus, 16)

        exponent_int = int(public_exponent, 16)

        key = RSA.construct((public_mod_int, exponent_int))
        self.bank_rsa = key
        self.bank_public_key = PKCS1_OAEP.new(key)

    def encrypt_deposit_code(self, value):
        return True

    def decrypt_user_deposit_code(self, encrypted_code):
        decrypted_code = self.decrypt(encrypted_code)
        amount = self._get_user_amount(decrypted_code)
        wallet_ids = self._get_wallet_ids(decrypted_code)
        return amount, wallet_ids

    def decrypt_bank_deposit_code(self, encrypted_code):
        amount = self._get_bank_amount(encrypted_code)
        return amount

    def generate_wallet_sync_code(self, wallet_id):
        return True

    def decrypt_wallet_sync_code(self, wallet_sync_code):
        # TODO:: decrypt and return WID and counter
        WID = ''
        counter = ''
        return WID, counter

    def _get_wallet_ids(self, record):
        # TODO:: get wallet ids from record
        wallet_id_a = ''
        wallet_id_b = ''
        wallet_map = {}
        wallet_map['wallet_id_a'] = wallet_id_a
        wallet_map['wallet_id_b'] = wallet_id_b
        return wallet_map

    def _get_bank_amount(self, record):
        # amount = self.bank_public_key.decrypt(record)
        amount = self.bank_rsa.decrypt(record)
            # rsa.decrypt(record, self.bank_public_cipher)
        return b64encode(amount)

    def _get_user_amount(self, record):
        amount = 0
        return amount

    def decrypt(self, code):
        return self.aes.AESCipher.decrypt(code)
