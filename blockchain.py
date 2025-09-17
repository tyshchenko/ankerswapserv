import os
import time
import hashlib
import requests
from ecdsa import SigningKey, SECP256k1
import web3
from web3.exceptions import InvalidTransaction
from web3.middleware import geth_poa_middleware
from eth_account import Account
#from solana.rpc.api import Client as SolanaClient
#from solana.keypair import Keypair
#from solana.transaction import Transaction
#from solana.system_program import transfer, TransferParams
import base58  # pip install base58
from tronpy import Tron  # pip install tronpy
from tronpy.keys import PrivateKey
from tronpy.providers import HTTPProvider
from bit import Key
from bit.transaction import (
    deserialize,
    address_to_scriptpubkey,
)


import json
import socket
import ssl
import bit

from models import GeneratedWallet, NewWallet, FullWallet
from config import COIN_SETTINGS, POLL_INTERVAL,PRKEY,ETHAPIKEY,BSCAPIKEY,TRONAPIKEY,VALRDEPOSIT

# Note: Install required libraries:
# pip3 install ecdsa web3 solana base58 tronpy requests

# Configuration - Replace with your own RPC URLs and central wallets
# For ETH: Get a free Infura/Alchemy project ID
# For SOL: Use a public RPC like https://api.mainnet-beta.solana.com
# For TRX: Use a public RPC like https://api.trongrid.io
# For BTC: Using BlockCypher API (rate-limited, consider alternatives for production)

def hex_to_bytes(hexed):

    if len(hexed) & 1:
        hexed = '0' + hexed

    return bytes.fromhex(hexed)

# Function to compute scripthash from a script (P2PKH or P2PK)
def script_to_scripthash(script_hex):
    try:
        # Convert script hex to bytes
        script = bytes.fromhex(script_hex)
        # SHA256 hash of the script
        scripthash = hashlib.sha256(script).digest()
        # Reverse the hash (ElectrumX uses little-endian)
        scripthash = scripthash[::-1]
        return scripthash.hex()
    except Exception as e:
        raise Exception(f"Error computing scripthash: {e}")

# Function to convert Bitcoin address to scripthash (P2PKH)
def address_to_scripthash(address):
    try:
        # Decode Base58 address to bytes
        decoded = base58.b58decode_check(address)
        # Extract pubkeyhash (remove version byte)
        pubkeyhash = decoded[1:]  # First byte is version, rest is hash
        # Create P2PKH script: OP_DUP OP_HASH160 <pubkeyhash> OP_EQUALVERIFY OP_CHECKSIG
        script = bytes.fromhex("76a914") + pubkeyhash + bytes.fromhex("88ac")
        return script_to_scripthash(script.hex())
    except Exception as e:
        raise Exception(f"Error converting address to scripthash: {e}")


# Basic synchronous JSON-RPC client for ElectrumX
class ElectrumXClient:
    def __init__(self, host, port, ssl=True):
        self.host = host
        self.port = port
        self.ssl = ssl
        self.socket = None
        self.id_counter = 0

    def connect(self):
        try:
            # Create socket
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            if self.ssl:
                # Wrap socket with SSL
                context = ssl.create_default_context()
                self.socket = context.wrap_socket(self.socket, server_hostname=self.host)
            self.socket.connect((self.host, self.port))
        except Exception as e:
            raise Exception(f"Connection error: {e}")

    def close(self):
        if self.socket:
            self.socket.close()
            self.socket = None

    def send_request(self, method, params):
        self.id_counter += 1
        request = {
            "jsonrpc": "2.0",
            "id": self.id_counter,
            "method": method,
            "params": params
        }
        # Serialize and send request
        request_data = json.dumps(request) + '\n'
        self.socket.sendall(request_data.encode('utf-8'))

        # Receive response
        response_data = ''
        while True:
            chunk = self.socket.recv(4096).decode('utf-8')
            if not chunk:
                break
            response_data += chunk
            if '\n' in response_data:
                break

        try:
            response = json.loads(response_data.strip())
            
#            print(response)
            return response
#            print("!!!!!!!!!!")
#            if "error" in response and response["error"] is not None:
#              print(f"RPC Error: ")
              #print(f"RPC Error: {response['error']}")
              #raise Exception(f"RPC Error: {response['error']}")
#              return {}

#            else:
#              return response["result"]
        except json.JSONDecodeError:
            raise Exception("Invalid JSON response from server")

    def get_history(self, scripthash):
        return self.send_request("blockchain.scripthash.get_history", [scripthash])

    def get_transaction(self, txid):
        return self.send_request("blockchain.transaction.get", [txid, True])


class Blockchain:
    def __init__(self):
        self.coins = COIN_SETTINGS
        self.hotmove = ['BTC','ETH','BNB','TRX']
        self.eth_client = web3.Web3(web3.HTTPProvider(COIN_SETTINGS['ETH']['rpc_url']))
        self.bnb_client = web3.Web3(web3.HTTPProvider(COIN_SETTINGS['BNB']['rpc_url']))
        self.bnb_client.middleware_onion.inject(geth_poa_middleware, layer=0)
#        self.sol_client = SolanaClient(COIN_SETTINGS['SOL']['rpc_url'])
        provider = HTTPProvider(timeout=30, endpoint_uri=COIN_SETTINGS['TRX']['rpc_url'])
        provider.sess.trust_env = False
        self.trx_client = Tron(provider)

    def get_balance(self, wallet: FullWallet):
        coin = wallet.coin
        if coin in self.coins:
          if coin == "BTC":
            balance = self.get_btc_balance(wallet.address)
            return str(balance)
          elif coin == "ETH":
            balance = self.get_eth_balance(wallet.address)
            return str(balance)
          elif coin == "BNB":
            balance = self.get_bnb_balance(wallet.address)
            return str(balance)
          elif coin == "TRX":
            balance = self.get_trx_balance(wallet.address)
            return str(balance)
          else:
            return '0'
        else:
          return '0'
        
    def move_from_hot(self):
#        VALRDEPOSIT
        newcache = self.hotmove.copy()
        for coin in newcache:
          try:
            if coin == "BTC":
              balance = self.get_btc_balance(COIN_SETTINGS[coin]['central_wallet'])
              print(str(balance))
              self.hotmove.remove(coin)
              if int(balance) > COIN_SETTINGS[coin]['min_send_amount']:
                self.send_btc_all(COIN_SETTINGS[coin]['central_wallet'], PRKEY, VALRDEPOSIT[coin]['address'])
            elif coin == "ETH":
              balance = self.get_eth_balance(COIN_SETTINGS[coin]['central_wallet'])
              print(str(balance))
              self.hotmove.remove(coin)
              if int(balance) > COIN_SETTINGS[coin]['min_send_amount']:
                self.send_eth_all(COIN_SETTINGS[coin]['central_wallet'], PRKEY, VALRDEPOSIT[coin]['address'])
            elif coin == "BNB":
              balance = self.get_bnb_balance(COIN_SETTINGS[coin]['central_wallet'])
              print(str(balance))
              self.hotmove.remove(coin)
              if int(balance) > COIN_SETTINGS[coin]['min_send_amount']:
                self.send_bnb_all(COIN_SETTINGS[coin]['central_wallet'], PRKEY, VALRDEPOSIT[coin]['address'])
            elif coin == "TRX":
              balance = self.get_trx_balance(COIN_SETTINGS[coin]['central_wallet'])
              print(str(balance))
              self.hotmove.remove(coin)
              if int(balance) > COIN_SETTINGS[coin]['min_send_amount']:
                self.send_trx_all(COIN_SETTINGS[coin]['central_wallet'], PRKEY, VALRDEPOSIT[coin]['address'])
          except Exception as e: print(e)
        print(self.hotmove)

    def get_transactions(self, wallet: FullWallet):
        coin = wallet.coin
        print(coin)
        if coin in self.coins:
          if coin == "BTC":
            transactions = self.get_btc_transactions(wallet.address)
            print(transactions)
            return transactions
          elif coin == "ETH":
            transactions = self.get_eth_transactions(wallet.address)
            return transactions
          elif coin == "BNB":
            transactions = self.get_bnb_transactions(wallet.address)
            return transactions
          elif coin == "TRX":
            transactions = self.get_tron_transactions(wallet.address)
            return transactions
          else:
            return []
        else:
          return []

    def forward_to_hot(self, wallet: FullWallet):
        coin = wallet.coin
        try:
          if coin in self.coins:
            if coin == "BTC":
              self.send_btc_all(wallet.address, wallet.privatekey, COIN_SETTINGS[coin]['central_wallet'])
              self.hotmove.append["BTC"]
            elif coin == "ETH":
              self.send_eth_all(wallet.address, wallet.privatekey, COIN_SETTINGS[coin]['central_wallet'])
              self.hotmove.append["ETH"]
            elif coin == "BNB":
              self.send_bnb_all(wallet.address, wallet.privatekey, COIN_SETTINGS[coin]['central_wallet'])
              self.hotmove.append["BNB"]
            elif coin == "TRX":
              self.send_trx_all(wallet.address, wallet.privatekey, COIN_SETTINGS[coin]['central_wallet'])
              self.hotmove.append["TRX"]
            else:
              return []
          else:
            return []
        except Exception as e: print(e)

    def generate_main_wallet(self):
        PRKEYb  = hex_to_bytes(PRKEY)
      
        address = self.generate_btc_address(PRKEYb)
        print(f"BTC Address: {address}")
        address = self.generate_eth_address(PRKEYb)
        print(f"eth Address: {address}")
        address = self.generate_bnb_address(PRKEYb)
        print(f"bnb Address: {address}")
        address = self.generate_trx_address(PRKEYb)
        print(f"trx Address: {address}")
#        address = self.generate_sol_address(PRKEYb)
#        print(f"sol Address: {address}")


    def generate_wallet(self, wallet: NewWallet) -> GeneratedWallet:
        coin = wallet.coin
        if coin in self.coins:
          private_key = os.urandom(32)
          print(f"Private Key (hex): {private_key.hex()}")
          if coin == "BTC":
            address = self.generate_btc_address(private_key)
            print(f"BTC Address: {address}")
            return GeneratedWallet(
                coin=coin,
                address=address,
                private_key=private_key.hex()
              )
          elif coin == "ETH":
            address = self.generate_eth_address(private_key)
            print(f"ETH Address: {address}")
            return GeneratedWallet(
                coin=coin,
                address=address,
                private_key=private_key.hex()
              )
          elif coin == "BNB":
            address = self.generate_bnb_address(private_key)
            print(f"BNB Address: {address}")
            return GeneratedWallet(
                coin=coin,
                address=address,
                private_key=private_key.hex()
              )
          #elif coin == "SOL":
            #address = self.generate_sol_address(private_key)
            #print(f"SOL Address: {address}")
            #return GeneratedWallet(
                #coin=coin,
                #address=address,
                #private_key=private_key.hex()
              #)
          elif coin == "TRX":
            address = self.generate_trx_address(private_key)
            print(f"TRX Address: {address}")
            return GeneratedWallet(
                coin=coin,
                address=address,
                private_key=private_key.hex()
              )
          else:
            return None
        else:
          return None



    def generate_btc_address(self, priv_key_bytes):
        key = Key.from_hex(priv_key_bytes.hex())
        address = key.segwit_address
        return address

    def generate_eth_address(self, priv_key_bytes):
        priv_key_eth = priv_key_bytes.hex()
        ethprivate_key = '0x'+priv_key_eth
        account     = Account.from_key(ethprivate_key)
        address  = account.address
        return address

    def generate_bnb_address(self, priv_key_bytes):
        priv_key_bnb = priv_key_bytes.hex()
        bnbprivate_key = '0x'+priv_key_bnb
        account     = Account.from_key(bnbprivate_key)
        address  = account.address
        return address

    #def generate_sol_address(self, priv_key_bytes):
        #keypair = Keypair.from_seed(priv_key_bytes)
        #address = base58.b58encode(keypair.public_key.to_bytes()).decode('utf-8')
        #return address

    def generate_trx_address(self, priv_key_bytes):
        private_key = PrivateKey(priv_key_bytes)
        address = private_key.public_key.to_base58check_address()
        return address


    def get_btc_transactions(self, address):
        url = f"https://blockstream.info/api/address/{address}/txs"
        response = requests.get(url)
        if response.status_code == 200:
            data = response.json()
            transactions = []
            for onetx in data:
              print(onetx)
              for outad in onetx['vout']:
                if outad['scriptpubkey_address'] == address:
                  transactions.append({
                    'hash':onetx['txid'],
                    'side':'Deposit',
                    'amount':outad['value'],
                  })
            
            return transactions
        return []

    def get_eth_transactions(self, address):
        url = f"https://api.etherscan.io/api?module=account&action=txlist&address={address}&sort=desc&apikey={ETHAPIKEY}"
        response = requests.get(url)
        
        if response.status_code == 200:
            data = response.json()
            if data.get("status") == "1":
                transactions = []
                for tx in data.get("result", []):
                    side = "Deposit" if tx["to"].lower() == address.lower() else "Sent to"
                    amount = int(tx["value"]) 
                    transactions.append({
                        "hash": tx["hash"],
                        "side": side,
                        "amount": amount
                    })
                return transactions
        return []

    def get_bnb_transactions(self, address):
        url = f"https://api.etherscan.io/v2/api?chainid=56&module=account&action=txlist&address={address}&sort=desc&apikey={BSCAPIKEY}"
        response = requests.get(url)
        if response.status_code == 200:
            data = response.json()
            if data.get("status") == "1":
                transactions = []
                for tx in data.get("result", []):
                    side = "Deposit" if tx["to"].lower() == address.lower() else "Sent to"
                    amount = int(tx["value"])
                    transactions.append({
                        "hash": tx["hash"],
                        "side": side,
                        "amount": amount
                    })
                return transactions
        return []


    def get_tron_transactions(self, address):
        url = f"https://api.tronscan.org/api/transaction?sort=-timestamp&limit=50&address={address}"
#        headers = {"TRON-PRO-API-KEY": TRONAPIKEY}
        headers = {"Content-Type": "application/json"}
        response = requests.get(url, headers=headers)
        print(response.text)
        if response.status_code == 200:
            data = response.json()
            transactions = []
            for tx in data.get("data", []):
                side = "Deposit" if tx["toAddress"] == address else "Sent to"
                amount = int(tx["amount"])
                transactions.append({
                    "hash": tx["hash"],
                    "side": side,
                    "amount": amount
                })
            return transactions
        return []
      
      
    def get_btc_balance(self, address):
        url = f"{COIN_SETTINGS['BTC']['rpc_url']}/addrs/{address}/balance"
        response = requests.get(url)
        print(response.text)
        if response.status_code == 200:
            data = response.json()
            return data['balance']  # in satoshis
        else:
          url = f"https://blockstream.info/api/address/{address}"
          response = requests.get(url)
          print(response.text)
          if response.status_code == 200:
              data = response.json()
              return data['chain_stats']['funded_txo_sum']  # in satoshis


        return 0

    def get_eth_balance(self, address):
        return self.eth_client.eth.get_balance(address)

    def get_bnb_balance(self, address):
        return self.bnb_client.eth.get_balance(address)

    #def get_sol_balance(self, address):
        #pubkey = Keypair.from_base58_string(address).public_key  # Wait, address is base58 of pubkey
        #response = self.sol_client.get_balance(address)
        #return response.value if 'value' in response else 0

    def get_trx_balance(self, address):
        try:
          balance = self.trx_client.get_account_balance(address) * 10**6
          return balance
        except Exception as e: 
          print(e)
          return 0

    def send_btc_all(self, address, priv_key_hex, central):
        # For BTC sending, it's more complex. Recommend using 'bit' library for simplicity.
        # pip install bit
        key = Key.from_hex(priv_key_hex)
        balance = self.get_btc_balance(address)
        if balance > COIN_SETTINGS['BTC']['min_send_amount']:
            # Estimate fee, bit handles it
            key.send([(central, balance / 10**8, 'btc')])  # bit handles fee automatically
            print("BTC sent to central")

    def send_eth_all(self, address, priv_key_bytes, central):
        balance = self.get_eth_balance(address)
        if balance > COIN_SETTINGS['ETH']['min_send_amount']:
            acct = self.eth_client.eth.account.from_key(priv_key_bytes)
            gas_price = self.eth_client.eth.gas_price
            gas = 21000
            value = balance - (gas * gas_price)
            if value > 0:
                nonce = self.eth_client.eth.get_transaction_count(address)
                tx = {
                    'nonce': nonce,
                    'to': central,
                    'value': value,
                    'gas': gas,
                    'gasPrice': gas_price,
                    'chainId': self.eth_client.eth.chain_id
                }
                signed_tx = acct.sign_transaction(tx)
                tx_hash = self.eth_client.eth.send_raw_transaction(signed_tx.raw_transaction)
                print(f"ETH sent: {tx_hash.hex()}")

    def send_bnb_all(self, address, priv_key_bytes, central):
        balance = self.get_bnb_balance(address)
        if balance > COIN_SETTINGS['BNB']['min_send_amount']:
            acct = self.bnb_client.eth.account.from_key(priv_key_bytes)
            gas_price = self.bnb_client.eth.gas_price
            gas = 21000
            value = balance - (gas * gas_price)
            if value > 0:
                nonce = self.bnb_client.eth.get_transaction_count(address)
                tx = {
                    'nonce': nonce,
                    'to': central,
                    'value': value,
                    'gas': gas,
                    'gasPrice': gas_price,
                    'chainId': self.bnb_client.eth.chain_id
                }
                signed_tx = acct.sign_transaction(tx)
                tx_hash = self.bnb_client.eth.send_raw_transaction(signed_tx.raw_transaction)
                print(f"BNB sent: {tx_hash.hex()}")

    #def send_sol_all(self, address, priv_key_bytes, central):
        #balance = self.get_sol_balance(address)
        #if balance > COIN_SETTINGS['SOL']['min_send_amount']:
            #keypair = Keypair.from_seed(priv_key_bytes)
            #txn = Transaction().add(
                #transfer(
                    #TransferParams(
                        #from_pubkey=keypair.public_key,
                        #to_pubkey=Keypair.from_base58_string(central).public_key,
                        #lamports=balance - 5000  # Approximate fee
                    #)
                #)
            #)
            #response = self.sol_client.send_transaction(txn, keypair)
            #print(f"SOL sent: {response['result']}")

    def send_trx_all(self, address, priv_key_bytes, central):
        PRKEYb  = hex_to_bytes(priv_key_bytes)
        priv_key = PrivateKey(PRKEYb)
        naddress = priv_key.public_key.to_base58check_address()
        balance = self.get_trx_balance(address)
        print(balance)
        print("TRX!!! " + naddress + " " + address)
        sendingamount = int(balance) - 2000000
        print(sendingamount)
        if balance > COIN_SETTINGS['TRX']['min_send_amount']:
            txn = (
                self.trx_client.trx.transfer(address, central, sendingamount)  # Leave some for fee
                .fee_limit(100 * 1000000)
                .build()
                .sign(priv_key)
            )
            result = txn.broadcast().wait()
            print(f"TRX sent: {result}")


    
blockchain = Blockchain()



#|  5 | viktor@ankerid.com    | ZAR  |                                            | 0       |         1 | 2025-09-11 13:10:00 | 2025-09-11 13:10:00 |                                                                  |
#|  6 | viktor@ankerid.com    | BTC  | 1LcQgtQRJostRv7vHmEauGVQs9dznp7Wtq         | 0       |         1 | 2025-09-11 13:24:54 | 2025-09-11 13:24:54 | 75db4b7fb0e30ae7951802d7884e613760fa4f04764162d2a6654a79cbf41b2a |
#|  7 | bobbyjonker@yahoo.com | ZAR  |                                            | 0       |         1 | 2025-09-11 14:18:34 | 2025-09-11 14:18:34 |                                                                  |
#|  8 | bobbyjonker@yahoo.com | BTC  | 1BeJVf7eArE43qdNQB1Yrcx87QVTUXgc98         | 0       |         1 | 2025-09-11 16:56:11 | 2025-09-11 16:56:11 | a5122e4e8217af2bd8f57e0e71b3b9983ffeb139ab5ce45904efbc321e958a87 |
#|  9 | viktor@ankerid.com    | ETH  | 0xb3e02d9648cdb0750eb42106fa3482c08399db5b | 0       |         1 | 2025-09-11 17:21:48 | 2025-09-11 17:21:48 | 09dcc7d0d68feecbbf6c42c3dc1f16ffbd54cab8c78d29535207f954b6ff8bf4 |
#| 10 | bobbyjonker@yahoo.com | ETH  | 0xa568e91fc79da57c5b617144fa8c65adfef7e8cf | 0       |         1 | 2025-09-11 17:26:07 | 2025-09-11 17:26:07 | 2eac5433ae9e28e17a06b663cd3548d5ef46fa9a73ecc5423416c6699bd3c701 |
