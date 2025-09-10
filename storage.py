from abc import ABC, abstractmethod
from typing import List, Optional, Dict
from datetime import datetime, timedelta
import random
import requests
import string

import pymysqlpool #pymysql-pool
from valr_python import Client

from models import User, InsertUser, Trade, InsertTrade, MarketData, InsertMarketData, Session, Wallet, BankAccount, NewWallet

from config import  DB_USER, DB_PASSWORD, DB_NAME, VALR_KEY, VALR_SECRET

class DataBase(object):
    def __init__(self, database):
        config={'host':'127.0.0.1', 'user':DB_USER, 'password':DB_PASSWORD, 'database':database, 'autocommit':True}
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
            return self.query(sqlquery)        
        
    
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


class IStorage(ABC):
    @abstractmethod
    def get_user(self, user_id: str) -> Optional[User]:
        pass

    @abstractmethod
    def get_user_by_username(self, username: str) -> Optional[User]:
        pass

    @abstractmethod
    def create_user(self, insert_user: InsertUser) -> User:
        pass

    @abstractmethod
    def create_trade(self, insert_trade: InsertTrade) -> Trade:
        pass

    @abstractmethod
    def get_user_trades(self, user_id: str) -> List[Trade]:
        pass

    @abstractmethod
    def get_market_data(self, pair: str) -> List[MarketData]:
        pass

    @abstractmethod
    def update_market_data(self, data: InsertMarketData) -> MarketData:
        pass

    @abstractmethod
    def get_all_market_data(self) -> List[MarketData]:
        pass
    
    # Authentication methods
    @abstractmethod
    def get_user_by_email(self, email: str) -> Optional[User]:
        pass
    
    @abstractmethod
    def get_user_by_google_id(self, google_id: str) -> Optional[User]:
        pass
    
    @abstractmethod
    def create_session(self, user_id: str, session_token: str, expires_at: datetime) -> Session:
        pass
    
    @abstractmethod
    def get_session(self, session_token: str) -> Optional[Session]:
        pass
    
    @abstractmethod
    def delete_session(self, session_token: str) -> bool:
        pass
    
    @abstractmethod
    def get_user_by_password_hash(self, password_hash: str) -> Optional[User]:
        pass


class MemStorage(IStorage):
    def __init__(self):

        self.trades: Dict[str, Trade] = {}
        self.market_data: Dict[str, List[MarketData]] = {}
        self.latest_prices: List[MarketData] = []
        self.sessions: Dict[str, Session] = {}
        self.pairs = ["BTC/ZAR", "ETH/ZAR", "USDT/ZAR", "BNB/ZAR", "TRX/ZAR", "SOL/ZAR"]
        self.activepairs = self.pairs
        self.usersfields = " id,email,username,password_hash,google_id,first_name,second_names,last_name,profile_image_url,is_active,created,updated,address,enabled2fa,code2fa,dob,gender,id_status,identity_number,referrer,sof,reference,phone "

        self._initialize_market_data()
        self.update_latest_prices()

    def _initialize_market_data(self):
        pairs = self.activepairs
        prices = self.get_prices()
        

        for pair in pairs:
            base_price = prices.get(pair.replace('/',''), float("1"))
            data = []
            url = "https://min-api.cryptocompare.com/data/v2/histohour?fsym=%s&tsym=%s&limit=72&e=CCCAGG" % (pair.split('/')[0],pair.split('/')[1])
            resutl = requests.get(url, headers={"Content-Type": "application/json"})
            data72 = resutl.json()

            # Generate 72 hours of hourly data
            for step in data72['Data']['Data']:
                
                data.append(MarketData(
                    pair=pair,
                    price=str(step['open']),
                    change_24h="0.00",
                    volume_24h=str(step['volumeto']),
                    timestamp=datetime.fromtimestamp(int(step['time'])/1000)
                ))
            
            self.market_data[pair] = data

    def randomstr(self, str_len):
        """---Get random string---"""
        return "".join(random.choice(string.digits + string.ascii_upercase) for _ in range(str_len))

    def create_reference(self, user_id):
        return 'APB' + str(user_id) + self.randomstr(6)

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
              

    def get_valr(self):
        c = Client(api_key=VALR_KEY, api_secret=VALR_SECRET)
        c.rate_limiting_support = True
        return c

    def get_prices(self):
        client = self.get_valr()
        prices = client.get_market_summary()
        pricedict = {}
        for price in prices:
          pricedict[price['currencyPair']] = price
        return pricedict

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
        print(wallets)
        if not wallets:
          new_zar_wallet = NewWallet(coin='ZAR')
          self.create_wallet(new_zar_wallet,user)
          wallets = db.query(sql)
        return wallets

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

    def create_wallet(self, new_wallet: NewWallet, user: User):
        sql = "INSERT INTO wallets (email,coin,address,balance) VALUE ('%s','%s','%s','0')" % (user.email,new_wallet.coin,new_wallet.address)
        db = DataBase(DB_NAME)
        lastrowid = db.execute(sql, return_id=True)


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

    def get_market_data(self, pair: str) -> List[MarketData]:
        return self.market_data.get(pair, [])

    def update_market_data(self, data: InsertMarketData) -> MarketData:
        market_data = MarketData(
            pair=data.pair,
            price=str(data.price),
            change_24h=str(data.change24h),
            volume_24h=str(data.volume24h),
            timestamp=datetime.now()
        )

        existing = self.market_data.get(data.pair, [])
        existing.append(market_data)
        
        # Keep only last 72 hours of data
        cutoff = datetime.now() - timedelta(hours=72)
        filtered = [d for d in existing if d.timestamp > cutoff]
        
        self.market_data[data.pair] = filtered
        return market_data

    def get_all_market_data(self) -> List[MarketData]:
        return self.latest_prices


# Global storage instance
storage = MemStorage()
