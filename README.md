# aes_bank_app
project for encryption coursework

a Python Flask app

For information on the APIs, query the /info endpoint
Usage:

/set_bank_public_key POST public_key: RSA public key

/user_deposit POST code: user provided encrypted deposit code

/bank_deposit POST emd_code: bank provided AES256 encrypted code value in hex, signature: PKCS1-RSA of SHA1 of the token in hex

/wallet_sync POST code: user provided encrypted sync code

/generate_deposit_code POST WIDA: sender's 4 byte wallet ID, WIDB: receiver's 4 byte wallet ID, amount: amount to transfer 4 bytes

/generate_wallet_sync WIDA: sender's 4 byte wallet ID, WIDB: receiver's 4 byte wallet ID