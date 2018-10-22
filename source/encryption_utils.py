import binascii
import hashlib
from base64 import b64decode, b64encode
import Crypto
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
        self.wallet_counter_map = {}

    def set_bank_public_key(self, bank_pu):
        public_modulus = 'CF9E0B601B6BD9335619470D3C22EED15D73B7D6D3AEB725FF4E458ED13D20D48027F2300A4346427E8FBB30C6F6C9E7AAC7B88AB3D376CCF5AF05E0B188CFA1F361F8B5B78C4E9EFC95A667B0AD26D5593FCAF629BB098AAFC7DF6F523D51450C9B7BF1A62EE4D3466D4D69D6B6C5E8488A6BC2BC70B09ED96753BA248516B3'
        public_exponent = '0x10001'
        # convert to byte array in preparation for conversion to hexadecimal

        public_mod_int = int(public_modulus, 16)

        exponent_int = int(public_exponent, 16)

        key = RSA.construct((public_mod_int, exponent_int))
        self.bank_rsa = key
        self.bank_public_key = PKCS1_OAEP.new(key, hashAlgo=Crypto.Hash.SHA256)

    def encrypt_deposit_code(self, WIDA, WIDB, amount, counter):
        # bytes 1-4: Sender’s Wallet ID
        # bytes 5-8: Receiver’s Wallet ID
        # bytes 9-12: Amount
        # bytes 13-16: Counter
        byte_str = ''
        wida_bytes = self.pad_bytes(WIDA)
        byte_str += wida_bytes

        widb_bytes = self.pad_bytes(WIDB)
        byte_str += widb_bytes

        amount_bytes = self.pad_bytes(amount)
        byte_str += amount_bytes

        counter_bytes = self.pad_bytes(counter)
        byte_str += counter_bytes

        print('Byte string: ' + byte_str + ' length: ' + str(byte_str.__len__()))
        code = self.aes.encrypt(byte_str)
        return code

    def pad_bytes(self, data):
        data = str(data)
        if data.__len__() < 4:
            print('byte arr before padding: ' + str(data) + ' length: ' + str(data.__len__()))
            data = data.rjust(4, '\0')
            print('byte arr after padding: ' + str(data) + ' length: ' + str(data.__len__()))
            return data
        else:
            return data

    def decrypt_user_deposit_code(self, encrypted_code):
        temp = ''
        #encrypted_bytes = bytearray.fromhex(encrypted_code)
        decrypted_code = self.decrypt(encrypted_code)
        amount = self._get_user_amount(decrypted_code)
        #wallet_ids = self._get_wallet_ids(decrypted_code)
        #return amount, wallet_ids
        return True

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

        # record_bytes = bytearray.fromhex(record)
        # amount = self.bank_rsa.decrypt(record_bytes)
        amount = self.bank_public_key.decrypt(record)
        return b64encode(amount)

    def _get_user_amount(self, record):
        # convert to bytes
        record = record.encode()
        amount = record[14:15]

        amount = 0
        return amount

    def decrypt(self, code):
        # TODO:: trim back to non-null length ... ?
        print('Code length in decrypt: ' + str(code.__len__()))
        code_arr = code.split('0x')
        print('Arr length' + str(code_arr.__len__()))

        code = b64decode(code)
        return self.aes.decrypt(code)

    def get_wallet_counter(self, wid):
        # get wallet id if it exists, otherwise return 0
        counter = self.wallet_counter_map[wid]
        if counter is None:
            self.wallet_counter_map[wid] = 0

    def incerment_wallet_counter(self, wid):
        counter = self.wallet_counter_map[wid]
        self.wallet_counter_map[wid] = counter + 1