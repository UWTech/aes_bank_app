import binascii
import hashlib
from base64 import b64decode, b64encode
import Crypto
import re
from Crypto.Cipher import AES
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA

class EncryptionUtils:

    def __init__(self, aes_key, account_details, bank_public_key=None):
        print('Preparing AES key')
        # convert to byte array in preparation for conversion to hexadecimal
        key_bytes = bytearray.fromhex('752EF0D8FB4958670DBA40AB1F3C1D0F8FB4958670DBA40AB1F3752EF0DC1D0F')
        print('byte array: ' + str(key_bytes))
        print('length: ' + str(key_bytes.__len__()))
        self.aes_key = bytes(key_bytes)
        self.bank_public_key = None
        self.bank_rsa = None
        self.account_details = account_details
        self.aes = AES.new(self.aes_key, AES.MODE_ECB)
        self.wallet_counter_map = {}
        self.set_bank_public_key(None)

    def set_bank_public_key(self, bank_pu):
        public_modulus = 'CF9E0B601B6BD9335619470D3C22EED15D73B7D6D3AEB725FF4E458ED13D20D48027F2300A4346427E8FBB30C6F6C9E7AAC7B88AB3D376CCF5AF05E0B188CFA1F361F8B5B78C4E9EFC95A667B0AD26D5593FCAF629BB098AAFC7DF6F523D51450C9B7BF1A62EE4D3466D4D69D6B6C5E8488A6BC2BC70B09ED96753BA248516B3'
        public_exponent = '010001'
        # convert to byte array in preparation for conversion to hexadecimal

        public_mod_int = int(bytes(bytearray.fromhex(public_modulus)).hex(), 16)

        exponent_int = int(bytes(bytearray.fromhex(public_exponent)).hex(), 16)

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
        decrypted_code = self.decrypt(encrypted_code)
        print('Byte sring in user deposit: ' + str(decrypted_code) + ' length: ' + str(encrypted_code.__len__()))
        amount = self._get_user_amount(decrypted_code)
        #return amount, wallet_ids TODO:: increment user counter in table
        return amount

    def decrypt_bank_deposit_code(self, encrypted_code):
        amount = self._get_bank_amount(encrypted_code)
        return amount

    def get_request_counter(self, code):
        decrypted_code = self.decrypt(code)
        counter = self._get_counter(decrypted_code)
        # convert bytes to string representation
        amount_string = counter.decode()
        regex_amount = re.sub('\x00', '', amount_string)
        counter = int(regex_amount)
        return counter

    def _get_counter(self, decrypted_code):
        record = bytearray(decrypted_code)
        counter = record[12:16]
        return counter

    def decrypt_wallet_sync_code(self, wallet_sync_code):
        # TODO:: decrypt and return WID and counter
        decrypted_code = self.decrypt(wallet_sync_code)
        decoded_dict = self._get_wallet_ids(decrypted_code)
        WID = decoded_dict['wallet_id_b'].decode('utf8')
        return WID

    def _get_wallet_ids(self, decrypted_code):
        record = bytearray(decrypted_code)
        wallet_id_a = record[0:4]
        wallet_id_b = record[4:8]
        wallet_map = {}
        wallet_map['wallet_id_a'] = wallet_id_a
        wallet_map['wallet_id_b'] = wallet_id_b
        return wallet_map

    def _get_bank_amount(self, record):
        bytes_record = bytes(bytearray.fromhex(record))
        emd_decrypted = self.aes.decrypt(bytes_record)
        emd_hex = emd_decrypted.hex()
        amount = int(emd_hex, 16)
        return amount

    def verify_signature(self, signature, emd_token):
        signer = PKCS1_v1_5.new(self.bank_rsa)
        digest = SHA.new()
        # Assumes the data is base64 encoded to begin with
        emd_token_encoded = bytes(bytearray.fromhex(emd_token)).hex()
        hex_encoded = emd_token_encoded.encode()
        digest.update(emd_token_encoded.encode())
        if signer.verify(digest, signature):
            return True
        return False

    def _get_user_amount(self, record):
        # convert to byte array for slicing
        record = bytearray(record)
        # slice out the amount
        amount = record[8:12]
        # convert bytes to string representation
        amount_string = amount.decode()
        print('string of bytes: ' + amount_string)
        # remove buffer (null) bytes if they exist
        regex_amount = re.sub('\x00', '', amount_string)
        # convert to integer
        amount = int(regex_amount)
        return amount

    def decrypt(self, code):
        # TODO:: trim back to non-null length ... ?

        code = b64decode(code)
        print('Code length in decrypt: ' + str(code.__len__()))
        return self.aes.decrypt(code)

    def get_wallet_counter(self, wid):
        # get wallet id if it exists, otherwise return 0
        self.wallet_counter_map[wid] = 0 # TODO:: remove counter
        counter = self.wallet_counter_map[wid]
        if counter is None:
            counter = 0
            self.wallet_counter_map[wid] = 0
        return counter

    def increment_wallet_counter(self, wid):
        try:
            counter = self.wallet_counter_map[wid]
            self.wallet_counter_map[wid] = counter + 1
        except Exception as e:
            self.wallet_counter_map[wid] = 1
