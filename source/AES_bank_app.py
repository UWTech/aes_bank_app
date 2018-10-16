from flask import Flask
from source.deposit import Deposit
from source import encryption_utils
from source.account_details import AccountDetails
from flask import Response, request
import json

app = Flask(__name__)

account_details = AccountDetails(WID='Eamon_Wallet', balance=0)
encryption_utils = encryption_utils.EncryptionUtils('752EF0D8FB4958670DBA40AB1F3C1D0F8FB4958670DBA40AB1F3752EF0DC1D0F',
                                                    account_details)
deposit_util = Deposit(encryption_utils)

@app.route('/info')
@app.route('/')
def info():
    Response.content_type = "text/plain"
    return """This is an AES encrypted banking app.
              Usage:
              /set_bank_public_key POST public_key: <RSA public key>
              /user_deposit POST code: <user provided encrypted deposit code>
              /bank_deposit POST code: <bank provided RSA encrypted code>
              /wallet_sync POST code: <user provided encrypted sync code>"""


@app.route('/set_bank_public_key')
def set_bank_pubic_key():
    data = request.data
    dataDict = json.loads(data)
    try:
        key = dataDict["public_key"]
        encryption_utils.set_bank_public_key(key)
        return Response('Public Key Set', 200)
    except Exception as e:
        print('failed to set key' + e)
        return Response('Failed to set Public Key', 400)


@app.route('/user_deposit', methods=['POST'])
def user_deposit():
    # decrypt code
    # check against sequence table
    # update account balance
    data = request.data
    dataDict = json.loads(data)
    code = dataDict["code"]
    print(code)
    try:
        value = deposit_util.user_deposit('junk')
        account_details.deposit(value)
        return Response('Balance:' + str(account_details.get_balance()), 200)
    except Exception as e:
        print('Failed to deposit' + e)
        return Response('Failed to deposit', 400)


@app.route('/bank_deposit', methods=['POST'])
def bank_deposit():
    data = request.data
    dataDict = json.loads(data)
    code = dataDict["code"]
    try:
        value = deposit_util.bank_deposit(code)
        account_details.deposit(value)
        return Response('Balance:' + str(account_details.get_balance()), 200)
    except Exception as e:
        print('Failed to deposit' + e)
        return Response('Failed to deposit', 400)


@app.route('/wallet_sync', methods=['POST'])
def wallet_sync():
    data = request.data
    dataDict = json.loads(data)
    code = dataDict["code"]
    try:
        wid, counter = encryption_utils.decrypt_wallet_sync_code(code)
        account_details.wallet_sync(wid, counter)
        return Response('Updated wallet sync', 200)
    except Exception as e:
        print('Failed to sync' + e)
        return Response('Failed to sync', 400)


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)
