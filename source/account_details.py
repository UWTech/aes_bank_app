
class AccountDetails:

    def __init__(self, WID, balance=0):
        self.balance = balance
        self.WID = WID
        self.wallet_sync_table = {}

    def withdraw(self, value):
        self.balance -= value

    def deposit(self, value):
        self.balance += int(value)

    def get_balance(self):
        return self.balance

    def wallet_sync(self, wallet_id, counter=None):
        if counter:
            self.wallet_sync_table[wallet_id] = counter
        elif wallet_id in self.wallet_sync_table:
            self.wallet_sync_table[wallet_id] += 1
        else:
            self.wallet_sync_table[wallet_id] = 0

    def get_wallet_sync_counter(self, wallet_id):
        return self.wallet_sync_table[wallet_id]
