from typing import List, Optional, Dict
from datetime import datetime, timedelta
import random
import requests
import string
import time
import threading


import pymysqlpool #pymysql-pool
from valr_python import Client

from models import User, InsertUser, Trade, InsertTrade, MarketData, Session, Wallet, BankAccount, NewWallet, FullWallet, NewBankAccount, OhlcvMarketData

from config import DB_USER, DB_PASSWORD, DB_NAME, DB_HOST, VALR_KEY, VALR_SECRET, COIN_SETTINGS, SUBACCOUNT
from blockchain import blockchain

class DataBase(object):
    def __init__(self, database):
        config={'host':DB_HOST, 'user':DB_USER, 'password':DB_PASSWORD, 'database':database, 'autocommit':True}
        self.pool0 = pymysqlpool.ConnectionPool(size=2, maxsize=7, pre_create_num=2, name='pool0', **config)
        
    def query(self, sqlquery):
        try:
            con1 = self.pool0.get_connection()
            cur = con1.cursor()
            cur.execute(sqlquery)
            rows = cur.fetchall()
            cur.close()
            con1.close()
            return rows
        except Exception as e:
            print(e)

            print('-reconnecting and trying again...')
            #return self.query(sqlquery)
            return None
        
    
    def execute(self, sqlquery, vals=None, return_id=False):
        try:
          con1 = self.pool0.get_connection()
          cur = con1.cursor()
          if not vals:
              cur.execute(sqlquery)
          else:
              cur.execute(sqlquery, vals)
          con1.commit()
          cur.close()
          con1.close()
          if return_id:
              return True, cur.lastrowid
          return True
        except Exception as e:
          print(e)
#          print('reconnecting and trying again...')
#          self.execute(sqlquery, vals, return_id)        



class MySqlStorage:
    def __init__(self):
        self.cache = {}

        self.trades: Dict[str, Trade] = {}
        self.market_data: Dict[str, Dict[str, List[MarketData]]] = {}
        self.ohlcv_market_data: Dict[str, Dict[str, List[OhlcvMarketData]]] = {}
        self.latest_prices: List[MarketData] = []
        self.sessions: Dict[str, Session] = {}
        self.pairs = ["BTC/ZAR", "ETH/ZAR", "USDT/ZAR", "BNB/ZAR", "TRX/ZAR", "SOL/ZAR"]
        self.activepairs = self.pairs
        self.usersfields = " id,email,username,password_hash,google_id,first_name,second_names,last_name,profile_image_url,is_active,created,updated,address,enabled2fa,code2fa,dob,gender,id_status,identity_number,referrer,sof,reference,phone "

        self._initialize_market_data()
        self.update_latest_prices()
        threading.Timer(120.0, self.cacheclearer).start()
#        print(self.get_miner_fee())
        print("!!!!!!!!!!!!!!!")
        print(self.get_all_balances())
        print("!!!!!!!!!!!!!!!")
        print(self.get_deposit_addresses())
        blockchain.move_from_hot()
        

    def cacheclearer(self):
      try:
        print("%s clean cache" % datetime.now())
        newcache = self.cache.copy()
        for key, value in newcache.items():
          try:
            if value['time'] < int(round(time.time()))-61:
                del self.cache[key]
          except Exception as e: print(e)
        del newcache
      except Exception as e: print(e)
      threading.Timer(120.0, self.cacheclearer).start()


    def reinitialize_market_data_1h(self):
        pairs = self.activepairs
        
        self.market_data['1H'] = {}
        self.ohlcv_market_data['1H'] = {}
          
        for pair in pairs:
            data = []
            ohlcvdata = []
            url = "https://min-api.cryptocompare.com/data/v2/histohour?fsym=%s&tsym=%s&limit=180&e=CCCAGG" % (pair.split('/')[0],pair.split('/')[1])
            result = requests.get(url, headers={"Content-Type": "application/json"})
            data72 = result.json()

            # Generate 180 hours of hourly data
            for step in data72['Data']['Data']:
                ohlcvdata.append(OhlcvMarketData(
                    pair=pair,
                    price=str(step['open']),
                    open=str(step['open']),
                    high=str(step['high']),
                    low=str(step['low']),
                    close=str(step['close']),
                    change_24h="0.00",
                    volume_24h=str(step['volumeto']),
                    timestamp=datetime.fromtimestamp(int(step['time']))
                ))
                
                data.append(MarketData(
                    pair=pair,
                    price=str(step['open']),
                    change_24h="0.00",
                    volume_24h=str(step['volumeto']),
                    timestamp=datetime.fromtimestamp(int(step['time']))
                ))
            
            self.ohlcv_market_data['1H'][pair] = ohlcvdata
            self.market_data['1H'][pair] = data
        print("1H re_initialized")




    def reinitialize_market_data_1d(self):
        pairs = self.activepairs
        self.market_data['1D'] = {}
        self.ohlcv_market_data['1D'] = {}
        for pair in pairs:
            data = []
            ohlcvdata = []
            url = "https://min-api.cryptocompare.com/data/v2/histoday?fsym=%s&tsym=%s&limit=180&e=CCCAGG" % (pair.split('/')[0],pair.split('/')[1])
            result = requests.get(url, headers={"Content-Type": "application/json"})
            data72 = result.json()

            # Generate 72 hours of hourly data
            for step in data72['Data']['Data']:
                ohlcvdata.append(OhlcvMarketData(
                    pair=pair,
                    price=str(step['open']),
                    open=str(step['open']),
                    high=str(step['high']),
                    low=str(step['low']),
                    close=str(step['close']),
                    change_24h="0.00",
                    volume_24h=str(step['volumeto']),
                    timestamp=datetime.fromtimestamp(int(step['time']))
                ))
                
                data.append(MarketData(
                    pair=pair,
                    price=str(step['open']),
                    change_24h="0.00",
                    volume_24h=str(step['volumeto']),
                    timestamp=datetime.fromtimestamp(int(step['time']))
                ))
            
            self.ohlcv_market_data['1D'][pair] = ohlcvdata
            self.market_data['1D'][pair] = data
        print("1D re_initialized")


    def reinitialize_market_data_1w(self):
        pairs = self.activepairs
        self.market_data['1W'] = {}
        self.ohlcv_market_data['1W'] = {}
        for pair in pairs:
            data = []
            ohlcvdata = []
            url = "https://min-api.cryptocompare.com/data/v2/histoday?fsym=%s&tsym=%s&limit=180&aggregate=7&e=CCCAGG" % (pair.split('/')[0],pair.split('/')[1])
            result = requests.get(url, headers={"Content-Type": "application/json"})
            data72 = result.json()

            # Generate 72 hours of hourly data
            for step in data72['Data']['Data']:
                ohlcvdata.append(OhlcvMarketData(
                    pair=pair,
                    price=str(step['open']),
                    open=str(step['open']),
                    high=str(step['high']),
                    low=str(step['low']),
                    close=str(step['close']),
                    change_24h="0.00",
                    volume_24h=str(step['volumeto']),
                    timestamp=datetime.fromtimestamp(int(step['time']))
                ))
                
                data.append(MarketData(
                    pair=pair,
                    price=str(step['open']),
                    change_24h="0.00",
                    volume_24h=str(step['volumeto']),
                    timestamp=datetime.fromtimestamp(int(step['time']))
                ))
            
            self.ohlcv_market_data['1W'][pair] = ohlcvdata
            self.market_data['1W'][pair] = data
        print("1W re_initialized")


    def reinitialize_market_data_1m(self):
        pairs = self.activepairs

        self.market_data['1M'] = {}
        self.ohlcv_market_data['1M'] = {}
        for pair in pairs:
            data = []
            ohlcvdata = []
            url = "https://min-api.cryptocompare.com/data/v2/histoday?fsym=%s&tsym=%s&limit=180&aggregate=30&e=CCCAGG" % (pair.split('/')[0],pair.split('/')[1])
            result = requests.get(url, headers={"Content-Type": "application/json"})
            data72 = result.json()

            # Generate 72 hours of hourly data
            for step in data72['Data']['Data']:
                ohlcvdata.append(OhlcvMarketData(
                    pair=pair,
                    price=str(step['open']),
                    open=str(step['open']),
                    high=str(step['high']),
                    low=str(step['low']),
                    close=str(step['close']),
                    change_24h="0.00",
                    volume_24h=str(step['volumeto']),
                    timestamp=datetime.fromtimestamp(int(step['time']))
                ))
                
                data.append(MarketData(
                    pair=pair,
                    price=str(step['open']),
                    change_24h="0.00",
                    volume_24h=str(step['volumeto']),
                    timestamp=datetime.fromtimestamp(int(step['time']))
                ))
            
            self.ohlcv_market_data['1M'][pair] = ohlcvdata
            self.market_data['1M'][pair] = data
        print("1M re_initialized")



    def _initialize_market_data(self):
        print("_initialize_market_data")
        self.reinitialize_market_data_1h()
        self.reinitialize_market_data_1d()
        self.reinitialize_market_data_1w()
        self.reinitialize_market_data_1m()
        print("_initialize_market_data DONE")
            

            
    def randomstr(self, str_len):
        """---Get random string---"""
        return "".join(random.choice(string.digits + string.ascii_uppercase) for _ in range(str_len))

    def create_reference(self, user_id):
        return 'APB' + str(user_id) + self.randomstr(6)

    def get_tx_hashes(self):
        db = DataBase(DB_NAME)
        uniqueidlist = []
        allidx = db.query("SELECT txhash FROM transactions group by txhash")
        for idx in allidx:
          uniqueidlist.append(idx[0])
        return uniqueidlist

    def fill_user(self, users) -> Optional[User]:
        if users:
          reference = users[0][21]
          if not reference:
            reference = self.create_reference(users[0][0])
            sql = "update users set reference='%s' where id=%s" % (reference,str(users[0][0]))
            db = DataBase(DB_NAME)
            lastrowid = db.execute(sql, return_id=True)
          user = User(
              id    = str(users[0][0]),
              email = users[0][1],
              username = users[0][2],
              password_hash = users[0][3],
              google_id = users[0][4],
              first_name = users[0][5],
              second_names = users[0][6],
              last_name = users[0][7],
              profile_image_url = users[0][8],
              is_active = users[0][9],
              created_at = users[0][10],
              updated_at = users[0][11],
              reference = reference,
              phone = users[0][22],
              two_factor_enabled = users[0][13],
            )
          
          return user
        else:
          return None

    def update_latest_prices(self):
        print("update_latest_prices")
        pairs = self.pairs
        prices = self.get_prices()
        
        all_data = []

        for pair in pairs:
            base_data = prices.get(pair.replace('/',''), None)
            timestamp = datetime.now()
            if base_data:
                data = MarketData(
                    pair=pair,
                    price=str(base_data['markPrice']),
                    change_24h=str(base_data['changeFromPrevious']),
                    volume_24h=str(base_data['quoteVolume']),
                    timestamp=timestamp
                )
                all_data.append(data)
                if pair in self.activepairs:
                  try:
                    self.market_data['1H'][pair][180].price = str(base_data['markPrice'])
                    self.market_data['1D'][pair][180].price = str(base_data['markPrice'])
                    self.market_data['1W'][pair][180].price = str(base_data['markPrice'])
                    self.market_data['1M'][pair][len(self.market_data['1M'][pair])-1].price = str(base_data['markPrice'])
                    self.ohlcv_market_data['1H'][pair][180].close = str(base_data['markPrice'])
                    self.ohlcv_market_data['1D'][pair][180].close = str(base_data['markPrice'])
                    self.ohlcv_market_data['1W'][pair][180].close = str(base_data['markPrice'])
                    self.ohlcv_market_data['1M'][pair][len(self.ohlcv_market_data['1M'][pair])-1].close = str(base_data['markPrice'])
                  except Exception as e: 
                    print(e)
                    
                
            else:
                data = MarketData(
                    pair=pair,
                    price='0',
                    change_24h='0',
                    volume_24h='0',
                    timestamp=timestamp
                )
                all_data.append(data)
        self.latest_prices = all_data
        print("update_latest_prices DONE")
              

    def get_valr(self):
        c = Client(api_key=VALR_KEY, api_secret=VALR_SECRET)
        c.rate_limiting_support = True
        return c

    def get_prices(self):
      key = 'getPrices'
      if key in self.cache:
        return self.cache[key]['data']
      else:
        client = self.get_valr()
        prices = client.get_market_summary()
        pricedict = {}
        for price in prices:
          pricedict[price['currencyPair']] = price
          
        jblock = {'time':int(round(time.time())), 'data':pricedict}
        self.cache[key] = jblock
        return pricedict

    def get_miner_fee(self):
      key = 'get_miner_fee'
      if key in self.cache:
        return self.cache[key]['data']
      else:
        client = self.get_valr()
        fees = {'ZAR':0}
        for coin in COIN_SETTINGS:
          winfo = client.get_crypto_withdrawal_info(coin)
          fees[coin] = float(winfo['withdrawCost'])

        jblock = {'time':int(round(time.time())), 'data':fees}
        self.cache[key] = jblock
        return fees




    def get_all_balances(self):
        client = self.get_valr()
        allbalances = client.get_nonzero_balances()

        return allbalances

    def get_deposit_addresses(self):
        client = self.get_valr()
        addresses = {'ZAR':''}
        for coin in COIN_SETTINGS:
          address = client.get_deposit_address(coin, SUBACCOUNT)
          addresses[coin] = address
          

        return addresses

    def move_pending_zar(self):
        client = self.get_valr()
        #allbalances = client.get_all_balances()
        sql = "select sum(pending + 0) from wallets where coin='ZAR'"
        db = DataBase(DB_NAME)
        pending_zar = db.query(sql)
        zaramount = float(pending_zar[0][0])
        if zaramount > 0:
          client.post_internal_transfer_subaccounts('0',SUBACCOUNT,'ZAR',str(int(zaramount)))
          sql = "update wallets set balance=(balance+0)+(pending+0), pending='0' where coin='ZAR' and pending != '0'"
          success, account_id = db.execute(sql, return_id=True)

    def move_pending_crypto(self):
        client = self.get_valr()
        #allbalances = client.get_all_balances()
        sql = "select sum(pending + 0), coin from wallets group by coin"
        db = DataBase(DB_NAME)
        pendings = db.query(sql)
        for pendingcrypto in pendings:
          amount = float(pendingcrypto[0])
          coin = pendingcrypto[1]
          if amount > 0 and coin !='ZAR':
            
            
            sql = "update wallets set balance=(balance+0)+(pending+0), pending='0' where coin='%s' and pending != '0'" % coin
            print(sql)
#            success, account_id = db.execute(sql, return_id=True)



    def get_user(self, user_id: str) -> Optional[User]:
        sql = "select "+self.usersfields+" from users where id=%s" % user_id
        db = DataBase(DB_NAME)
        users = db.query(sql)
        return self.fill_user(users)
      
    def get_user_by_username(self, username: str) -> Optional[User]:
        sql = "select "+self.usersfields+" from users where username='%s'" % username
        db = DataBase(DB_NAME)
        users = db.query(sql)
        return self.fill_user(users)
    
    def get_user_by_email(self, email: str) -> Optional[User]:
        sql = "select "+self.usersfields+" from users where email='%s'" % email
        db = DataBase(DB_NAME)
        users = db.query(sql)
        return self.fill_user(users)
        
    def check_user_exist(self, insert_user: InsertUser) -> Optional[User]:
        sql = "select "+self.usersfields+" from users where email='%s' or username='%s' or google_id='%s'" % (insert_user.email,insert_user.username,insert_user.google_id)
        db = DataBase(DB_NAME)
        users = db.query(sql)
        return self.fill_user(users)
        
    def get_user_by_google_id(self, google_id: str) -> Optional[User]:
        sql = "select "+self.usersfields+" from users where google_id='%s'" % google_id
        db = DataBase(DB_NAME)
        users = db.query(sql)
        return self.fill_user(users)

    def get_user_by_password_hash(self, password_hash: str) -> Optional[User]:
        sql = "select "+self.usersfields+" from users where password_hash='%s'" % password_hash
        db = DataBase(DB_NAME)
        users = db.query(sql)
        return self.fill_user(users)
        
    def get_wallets(self, user: User) -> Optional[List[Wallet]]:
        sql = "select id,email,coin,address,balance,is_active,created,updated from wallets where email='%s'" % user.email
        db = DataBase(DB_NAME)
        wallets = db.query(sql)
        if not wallets:
          new_zar_wallet = NewWallet(coin='ZAR')
          self.create_wallet(new_zar_wallet,user)
          wallets = db.query(sql)
        return wallets

    def get_all_wallets(self, coins) -> Optional[List[FullWallet]]:
        sql = "select id,email,coin,address,balance,is_active,privatekey,created,updated,hotwalet from wallets where is_active=1 and privatekey>'' and coin IN('%s')" % ("','".join(coins))
        db = DataBase(DB_NAME)
        wallets = db.query(sql)
        allwallets = []
        for wallet in wallets:
          allwallets.append(FullWallet(
                email = wallet[1],
                coin = wallet[2],
                address = wallet[3],
                balance = wallet[4],
                hotwalet = wallet[9],
                is_active = wallet[5],
                privatekey = wallet[6],
                created_at = wallet[7],
                updated_at = wallet[8],
            ))
        return allwallets

    def update_wallet_balance(self, wallet: FullWallet, walletbalance, hasheslist):
        txhashes = hasheslist
        prevbalance = float(wallet.balance)
        transactions = []
        if float(walletbalance) == 0 and wallet.coin == 'BTC':
          transactions = []
        else:
          transactions = blockchain.get_transactions(wallet)
#        print(transactions)
        for tx in transactions:
          if tx['hash'] not in txhashes:
            txhashes.append(tx['hash'])
            db = DataBase(DB_NAME)
            if tx['side'] == 'Deposit':
              minerfee = self.get_miner_fee(wallet.coin)
              tocoinamount = COIN_SETTINGS[wallet.coin]['format'] % (int(tx['amount'])/COIN_SETTINGS[wallet.coin]['decimals']+prevbalance-minerfee)
              sql = "UPDATE wallets set balance='%s', hotwalet='%s'  where privatekey='%s' and email='%s' and coin='%s'" % (tocoinamount,walletbalance,wallet.privatekey,wallet.email,wallet.coin)
              success, account_id = db.execute(sql, return_id=True)
            
              deposittocoinamount = COIN_SETTINGS[wallet.coin]['format'] % (int(tx['amount'])/COIN_SETTINGS[wallet.coin]['decimals'])
              sql = "INSERT INTO transactions (email, coin, side, amount, price, status, txhash, txtype) VALUES ('%s','%s','%s','%s','0','complete', '%s', 'user')" % (
                    wallet.email, wallet.coin, tx['side'], deposittocoinamount, tx['hash']
              )
              success, account_id = db.execute(sql, return_id=True)

              sql = "INSERT INTO transactions (email, coin, side, amount, price, status, txhash, txtype) VALUES ('%s','%s','Fee','%s','0','complete', '%s', 'user')" % (
                    wallet.email, wallet.coin, (COIN_SETTINGS[wallet.coin]['format'] % (int(minerfee))), tx['hash']
              )
              success, account_id = db.execute(sql, return_id=True)
            else:
              deposittocoinamount = COIN_SETTINGS[wallet.coin]['format'] % (int(tx['amount'])/COIN_SETTINGS[wallet.coin]['decimals'])
              sql = "INSERT INTO transactions (email, coin, side, amount, price, status, txhash, txtype) VALUES ('%s','%s','%s','%s','0','complete', '%s', 'system')" % (
                    wallet.email, wallet.coin, tx['side'], deposittocoinamount, tx['hash']
              )
              success, account_id = db.execute(sql, return_id=True)
              sql = "UPDATE wallets set hotwalet='%s'  where privatekey='%s' and email='%s' and coin='%s'" % (walletbalance,wallet.privatekey,wallet.email,wallet.coin)
              success, account_id = db.execute(sql, return_id=True)


        return txhashes

    def get_bankaccounts(self, user: User) -> Optional[BankAccount]:
        sql = "select id,email,account_name,account_number,branch_code,created,updated from bank_accounts where email='%s'" % user.email
        db = DataBase(DB_NAME)
        bankaccounts = db.query(sql)
        if bankaccounts:
          return bankaccounts[0]
        else:
          return None

    
    def create_session(self, user_id: str, session_token: str, expires_at: datetime) -> Session:
        session = Session(
            user_id=user_id,
            session_token=session_token,
            expires_at=expires_at
        )
        self.sessions[session_token] = session
        return session
    
    def get_session(self, session_token: str) -> Optional[Session]:
        session = self.sessions.get(session_token)
        if session and session.expires_at > datetime.now():
            return session
        elif session:
            # Clean up expired session
            del self.sessions[session_token]
        return None
    
    def delete_session(self, session_token: str) -> bool:
        if session_token in self.sessions:
            del self.sessions[session_token]
            return True
        return False

    def create_user(self, insert_user: InsertUser) -> User:
        sql = "INSERT INTO users (email,username,password_hash,google_id,first_name,last_name,profile_image_url) VALUE ('%s','%s','%s','%s','%s','%s','%s')" % (insert_user.email,insert_user.username,insert_user.password_hash,insert_user.google_id,insert_user.first_name,insert_user.last_name,insert_user.profile_image_url)
        db = DataBase(DB_NAME)
        lastrowid = db.execute(sql, return_id=True)
        
        user = self.get_user_by_email(insert_user.email)
        return user

    def create_wallet(self, new_wallet: NewWallet, user: User) -> Wallet:
        generated = blockchain.generate_wallet(new_wallet)
        address=''
        private_key=''
        coin=new_wallet.coin
        if generated:
          address=generated.address
          private_key=generated.private_key
          
        sql = "INSERT INTO wallets (email,coin,address,balance,privatekey) VALUES ('%s','%s','%s','0','%s')" % (user.email,coin,address,private_key)
        db = DataBase(DB_NAME)
        lastrowid = db.execute(sql, return_id=True)
        return Wallet(
            email = user.email,
            coin = coin,
            address = address,
            balance = "0",
            is_active = True,
          )

    def create_bank_account(self, new_bank_account: NewBankAccount, user: User) -> dict:
        """Create a new bank account for user"""
        # Check if user already has a bank account
        check_sql = "SELECT id FROM bank_accounts WHERE email='%s'" % user.email
        db = DataBase(DB_NAME)
        existing = db.query(check_sql)
        if existing:
            raise ValueError("User already has a bank account")
        
        # Insert new bank account
        sql = "INSERT INTO bank_accounts (email, account_name, account_number, branch_code) VALUES ('%s','%s','%s','%s')" % (
            user.email, new_bank_account.accountName, new_bank_account.accountNumber, new_bank_account.branchCode
        )
        success, account_id = db.execute(sql, return_id=True)
        
        if success:
            # Fetch the created account
            fetch_sql = "SELECT id, email, account_name, account_number, branch_code, created, updated FROM bank_accounts WHERE id=%s" % account_id
            account_data = db.query(fetch_sql)
            if account_data:
                account_row = account_data[0]
                return {
                    "id": str(account_row[0]),
                    "email": account_row[1],
                    "account_name": account_row[2],
                    "account_number": account_row[3],
                    "branch_code": account_row[4],
                    "created": account_row[5].isoformat() if account_row[5] else None,
                    "updated": account_row[6].isoformat() if account_row[6] else None
                }
        
        raise Exception("Failed to create bank account")

    def get_bank_accounts(self, user: User) -> List[dict]:
        """Get all bank accounts for user"""
        sql = "SELECT id, email, account_name, account_number, branch_code, created, updated FROM bank_accounts WHERE email='%s'" % user.email
        db = DataBase(DB_NAME)
        accounts = db.query(sql)
        
        result = []
        if accounts:
            for account_row in accounts:
                result.append({
                    "id": str(account_row[0]),
                    "email": account_row[1],
                    "account_name": account_row[2],
                    "account_number": account_row[3],
                    "branch_code": account_row[4],
                    "created": account_row[5].isoformat() if account_row[5] else None,
                    "updated": account_row[6].isoformat() if account_row[6] else None
                })
        
        return result

    def create_trade(self, insert_trade: InsertTrade) -> Trade:
        trade = Trade(
            user_id=insert_trade.userId,
            type=insert_trade.type,
            from_asset=insert_trade.fromAsset,
            to_asset=insert_trade.toAsset,
            from_amount=insert_trade.fromAmount,
            to_amount=insert_trade.toAmount,
            rate=insert_trade.rate,
            fee=insert_trade.fee,
            status="completed",
            created_at=datetime.now()
        )
        self.trades[trade.id] = trade
        return trade

    def get_user_trades(self, user_id: str) -> List[Trade]:
        user_trades = [
            trade for trade in self.trades.values() 
            if trade.userId == user_id
        ]
        return sorted(user_trades, key=lambda t: t.createdAt, reverse=True)

    def get_user_transactions(self, user_id: str) -> List[Trade]:
        user_trades = [
            trade for trade in self.trades.values() 
            if trade.userId == user_id
        ]
        return sorted(user_trades, key=lambda t: t.createdAt, reverse=True)

    def get_market_data(self, pair: str, timeframe: str, charttype: str) -> List[OhlcvMarketData]:
        if charttype == 'OHLCV':
          timedata = self.ohlcv_market_data.get(timeframe, None)
          if timedata:
            return timedata.get(pair, [])
          else:
            return []
        else:
          timedata = self.market_data.get(timeframe, None)
          if timedata:
            return timedata.get(pair, [])
          else:
            return []



    def get_all_market_data(self) -> List[MarketData]:
        return self.latest_prices


# Global storage instance
storage = MySqlStorage()
