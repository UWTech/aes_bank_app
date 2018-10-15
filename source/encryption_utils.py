

class EncryptionUtils:

    def __init__(self, aes_key, account_details, bank_public_key):
        self.aes_key = aes_key
        self.bank_public_key
        self.account_details = account_details
        self.bank_public_key = bank_public_key

    def encrypt_deposit_code(self, value):
        return True

    def decrypt_user_deposit_code(self, encrypted_code):
        decrypted_code = self.decrypt(encrypted_code)
        amount = self._get_user_amount(decrypted_code)
        wallet_ids = self._get_wallet_ids(decrypted_code)
        return amount, wallet_ids

    def decrypt_bank_deposit_code(self, encrypted_code):
        # TODO:: decrypt using bank public key
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
        # TODO:: get amount
        amount = 0
        return amount

    def _get_user_amount(self, record):
        # TODO:: get amount
        amount = 0
        return amount

    def decrypt(self, code):
        # TODO:: decrypt
        return True