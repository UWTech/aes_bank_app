
class AccountDetails:

    def __init__(self, WID, balance=0):
        self.balance = balance
        self.WID = WID
        self.wallet_sync_table = {}

    def withdraw(self, value):
        self.balance -= value

    def deposit(self, value):
        self.balance += value

    def get_balance(self):
        return self.balance

    def wallet_sync(self, wallet_id, counter):
        self.wallet_sync_table[wallet_id] = counter + 1

    def get_wallet_sync_counter(self, wallet_id):
        return self.wallet_sync_table[wallet_id]
