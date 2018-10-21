
class Deposit:

    def __init__(self, encryption_utils):
        self.encryption_utils = encryption_utils

    def user_deposit(self, deposit_code):
        try:
            amount = self.encryption_utils.decrypt_user_deposit_code(deposit_code)
        except Exception as e:
            print('Failed to deposit:' + e)

        return amount

    def bank_deposit(self, deposit_code):
        try:
            amount = self.encryption_utils.decrypt_bank_deposit_code(deposit_code)
        except Exception as e:
            raise e

        return amount