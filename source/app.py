from flask import Flask
from flask import jsonify
from source.deposit import Deposit
from source import encryption_utils
from source.account_details import AccountDetails
from flask import Response, request
import json
import base64

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
              /bank_deposit POST emd_code: <bank provided AES256 encrypted code value in hex>, signature: <PKCS1-RSA of SHA1 of the token in hex>
              /wallet_sync POST code: <user provided encrypted sync code>
              /generate_deposit_code POST WIDA: <sender's 4 byte wallet ID>, WIDB: <receiver's 4 byte wallet ID>, amount: <amount to transfer 4 bytes>
              /generate_wallet_sync WIDA: <sender's 4 byte wallet ID>, WIDB: <receiver's 4 byte wallet ID>"""


@app.route('/set_bank_public_key', methods=["POST"])
def set_bank_pubic_key():
    data = request.data
    dataDict = json.loads(data)
    try:
        key = dataDict["public_key"]
        encryption_utils.set_bank_public_key(key)
        return Response('Public Key Set', 200)
    except Exception as e:
        print(e)
        raise e
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
        value = deposit_util.user_deposit(code)
        wallet_id = encryption_utils.decrypt_wallet_sync_code(code)
        current_counter = account_details.get_wallet_sync_counter(wallet_id)
        request_counter = encryption_utils.get_request_counter(code)

        if current_counter != request_counter:
            return Response('counters do not match', 400)

        account_details.wallet_sync(wallet_id)
        account_details.deposit(value)
        return Response('Balance:' + str(account_details.get_balance()), 200)
    except Exception as e:
        print(e)
        return Response('Failed to deposit', 400)


@app.route('/bank_deposit', methods=['POST'])
def bank_deposit():
    data = request.data
    dataDict = json.loads(data)
    emd_token = dataDict["emd"]
    signature = dataDict["signature"]
    print('Bank deposit code: ' + emd_token)
    try:
        value = deposit_util.bank_deposit(emd_token)
        verified = encryption_utils.verify_signature(signature, emd_token)
        if not verified:
            print('Value: ' + str(value))
            return Response('Invalid Signature!', 400)
        # else, valid, complete deposit
        print('Value: ' + str(value))
        account_details.deposit(value)
        return Response('funds deposited', 200)
    except Exception as e:
        raise e
        return Response('Failed to deposit', 400)



@app.route('/wallet_sync', methods=['POST'])
def wallet_sync():
    data = request.data
    dataDict = json.loads(data)
    code = dataDict["code"]
    try:
        wid = encryption_utils.decrypt_wallet_sync_code(code)
        account_details.wallet_sync(wid)
        return Response('Updated wallet sync', 200)
    except Exception as e:
        print(e)
        return Response('Failed to sync', 400)


@app.route('/generate_wallet_sync', methods=['POST'])
def generate_wallet_sync():
    data = request.data
    dataDict = json.loads(data)
    WIDA = dataDict["WIDA"]
    WIDB = dataDict["WIDB"]
    try:
        code = encryption_utils.encrypt_deposit_code(WIDA, WIDB, 0, 0)
        return Response(base64.encodebytes(code), 200)
    except Exception as e:
        raise e
        return Response('Failed to generate deposit code', 400)


#TODO:: convert to hex
@app.route('/generate_deposit_code', methods=['POST'])
def generate_deposit_code():
    data = request.data
    dataDict = json.loads(data)
    WIDA = dataDict["WIDA"]
    WIDB = dataDict["WIDB"]
    amount = dataDict["amount"]
    try:
        counter = encryption_utils.get_wallet_counter(WIDB)
        code = encryption_utils.encrypt_deposit_code(WIDA, WIDB, amount, counter)
        encryption_utils.increment_wallet_counter(WIDB)
        account_details.withdraw(float(amount))
        json_code = base64.encodebytes(code)
        account_details.wallet_sync(WIDB)
        return Response(json_code, 200)
    except Exception as e:
        raise e
        return Response('Failed to generate deposit code', 400)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)
