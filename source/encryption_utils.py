import rsa
import binascii
import hashlib
from Crypto.Cipher import AES


class EncryptionUtils:

    def __init__(self, aes_key, account_details, bank_public_key=None):
        # convert to byte array in preparation for conversion to hexadecimal
        key_bytes = bytearray('752EF0D8FB4958670DBA40AB1F3C1D0F8FB4958670DBA40AB1F3752EF0DC1D0F', 'utf8')
        print('byte array: ' + str(key_bytes))
        # convert byte array to hexadecimal in preparation of generating a SHA256 digest
        hex_key = binascii.hexlify(key_bytes)
        print('hex key string: ' + str(hex_key))
        # create instance of SHA256
        h = hashlib.sha256()
        # hash the hexadecimal representation of the key
        h.update(hex_key)
        # generate the digest to serve as the AES key
        self.aes_key = h.digest()
        self.bank_public_key = bank_public_key
        self.account_details = account_details
        self.bank_public_key = bank_public_key
        self.aes = AES.new(self.aes_key, AES.MODE_ECB)

    def set_bank_public_key(self, bank_pu):
        self.bank_public_key = bank_pu

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
        amount = rsa.decrypt(record, self.bank_public_key)
        return amount

    def _get_user_amount(self, record):
        amount = 0
        return amount

    def decrypt(self, code):
        return self.aes.AESCipher.decrypt(code)
