import psycopg2
from psycopg2.extras import RealDictCursor
import os
from typing import List, Optional, Dict
from datetime import datetime, timedelta
import random
import requests
import string
import uuid

from valr_python import Client
from models import User, InsertUser, Trade, InsertTrade, MarketData, InsertMarketData, Session, Wallet, BankAccount, NewWallet, NewBankAccount
from config import VALR_KEY, VALR_SECRET


class PostgresStorage:
    def __init__(self):
        self.database_url = os.getenv('DATABASE_URL')
        self.trades: Dict[str, Trade] = {}
        self.market_data: Dict[str, List[MarketData]] = {}
        self.latest_prices: List[MarketData] = []
        self.sessions: Dict[str, Session] = {}
        self.pairs = ["BTC/ZAR", "ETH/ZAR", "USDT/ZAR", "BNB/ZAR", "TRX/ZAR", "SOL/ZAR"]
        self.activepairs = self.pairs
        
        # Initialize database tables
        self._create_tables()
        self._initialize_market_data()
        self.update_latest_prices()

    def get_connection(self):
        """Get database connection"""
        return psycopg2.connect(self.database_url)

    def _create_tables(self):
        """Create necessary database tables"""
        with self.get_connection() as conn:
            with conn.cursor() as cur:
                # Users table
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS users (
                        id SERIAL PRIMARY KEY,
                        email VARCHAR(255) UNIQUE,
                        username VARCHAR(255),
                        password_hash TEXT,
                        google_id VARCHAR(255),
                        first_name VARCHAR(255),
                        second_names VARCHAR(255),
                        last_name VARCHAR(255),
                        profile_image_url TEXT,
                        is_active BOOLEAN DEFAULT TRUE,
                        created TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        reference VARCHAR(255),
                        phone VARCHAR(50),
                        enabled2fa BOOLEAN DEFAULT FALSE
                    );
                """)
                
                # Wallets table
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS wallets (
                        id SERIAL PRIMARY KEY,
                        email VARCHAR(255),
                        coin VARCHAR(10),
                        address TEXT,
                        balance DECIMAL(20, 8) DEFAULT 0,
                        is_active BOOLEAN DEFAULT TRUE,
                        created TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    );
                """)
                
                # Bank accounts table
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS bank_accounts (
                        id SERIAL PRIMARY KEY,
                        email VARCHAR(255),
                        account_name VARCHAR(255),
                        account_number VARCHAR(255),
                        branch_code VARCHAR(20),
                        created TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    );
                """)
                
                conn.commit()

    def _initialize_market_data(self):
        """Initialize market data from external API"""
        pairs = self.activepairs
        prices = self.get_prices()
        
        for pair in pairs:
            base_price = prices.get(pair.replace('/',''), float("1"))
            data = []
            try:
                url = "https://min-api.cryptocompare.com/data/v2/histohour?fsym=%s&tsym=%s&limit=72&e=CCCAGG" % (pair.split('/')[0],pair.split('/')[1])
                result = requests.get(url, headers={"Content-Type": "application/json"})
                data72 = result.json()

                # Generate 72 hours of hourly data
                for step in data72['Data']['Data']:
                    data.append(MarketData(
                        pair=pair,
                        price=str(step['open']),
                        change_24h="0.00",
                        volume_24h=str(step['volumeto']),
                        timestamp=datetime.fromtimestamp(int(step['time']))
                    ))
                
                self.market_data[pair] = data
            except Exception as e:
                print(f"Error initializing market data for {pair}: {e}")
                # Create default data if API fails
                self.market_data[pair] = [MarketData(
                    pair=pair,
                    price="1.00",
                    change_24h="0.00",
                    volume_24h="0.00",
                    timestamp=datetime.now()
                )]

    def randomstr(self, str_len):
        """Get random string"""
        return "".join(random.choice(string.digits + string.ascii_uppercase) for _ in range(str_len))

    def create_reference(self, user_id):
        return 'APB' + str(user_id) + self.randomstr(6)

    def update_latest_prices(self):
        """Update latest market prices"""
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
        if VALR_KEY and VALR_SECRET:
            c = Client(api_key=VALR_KEY, api_secret=VALR_SECRET)
            c.rate_limiting_support = True
            return c
        return None

    def get_prices(self):
        """Get prices from VALR API or return mock data"""
        try:
            client = self.get_valr()
            if client:
                prices = client.get_market_summary()
                pricedict = {}
                for price in prices:
                    pricedict[price['currencyPair']] = price
                return pricedict
        except Exception as e:
            print(f"Error fetching prices from VALR: {e}")
        
        # Return mock data if API fails
        return {
            'BTCZAR': {'markPrice': '1000000', 'changeFromPrevious': '2.5', 'quoteVolume': '1000000'},
            'ETHZAR': {'markPrice': '50000', 'changeFromPrevious': '1.8', 'quoteVolume': '500000'},
            'USDTZAR': {'markPrice': '18.50', 'changeFromPrevious': '0.1', 'quoteVolume': '100000'},
        }

    def get_user(self, user_id: str) -> Optional[User]:
        """Get user by ID"""
        with self.get_connection() as conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("SELECT * FROM users WHERE id = %s", (user_id,))
                row = cur.fetchone()
                if row:
                    return self._row_to_user(row)
        return None

    def get_user_by_email(self, email: str) -> Optional[User]:
        """Get user by email"""
        with self.get_connection() as conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("SELECT * FROM users WHERE email = %s", (email,))
                row = cur.fetchone()
                if row:
                    return self._row_to_user(row)
        return None

    def get_user_by_google_id(self, google_id: str) -> Optional[User]:
        """Get user by Google ID"""
        with self.get_connection() as conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("SELECT * FROM users WHERE google_id = %s", (google_id,))
                row = cur.fetchone()
                if row:
                    return self._row_to_user(row)
        return None

    def _row_to_user(self, row) -> User:
        """Convert database row to User object"""
        reference = row['reference']
        if not reference:
            reference = self.create_reference(row['id'])
            with self.get_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute("UPDATE users SET reference = %s WHERE id = %s", (reference, row['id']))
                    conn.commit()
        
        return User(
            id=str(row['id']),
            email=row['email'],
            username=row['username'],
            password_hash=row['password_hash'],
            google_id=row['google_id'],
            first_name=row['first_name'],
            second_names=row['second_names'],
            last_name=row['last_name'],
            profile_image_url=row['profile_image_url'],
            is_active=row['is_active'],
            created_at=row['created'],
            updated_at=row['updated'],
            reference=reference,
            phone=row['phone'],
            two_factor_enabled=row['enabled2fa']
        )

    def create_user(self, insert_user: InsertUser) -> User:
        """Create a new user"""
        with self.get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO users (email, username, password_hash, google_id, first_name, last_name, profile_image_url)
                    VALUES (%s, %s, %s, %s, %s, %s, %s)
                    RETURNING id
                """, (
                    insert_user.email, 
                    insert_user.username, 
                    insert_user.password_hash, 
                    insert_user.google_id,
                    insert_user.first_name, 
                    insert_user.last_name, 
                    insert_user.profile_image_url
                ))
                user_id = cur.fetchone()[0]
                conn.commit()
        
        return self.get_user(str(user_id))

    def get_wallets(self, user: User) -> Optional[List]:
        """Get user wallets"""
        with self.get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT * FROM wallets WHERE email = %s", (user.email,))
                wallets = cur.fetchall()
                
                if not wallets:
                    # Create default ZAR wallet
                    cur.execute("""
                        INSERT INTO wallets (email, coin, address, balance)
                        VALUES (%s, 'ZAR', NULL, 0)
                    """, (user.email,))
                    conn.commit()
                    cur.execute("SELECT * FROM wallets WHERE email = %s", (user.email,))
                    wallets = cur.fetchall()
                
                return wallets

    def create_wallet(self, new_wallet: NewWallet, user: User) -> dict:
        """Create a new wallet for user"""
        with self.get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO wallets (email, coin, address, balance)
                    VALUES (%s, %s, %s, 0)
                    RETURNING id, email, coin, address, balance, is_active, created, updated
                """, (user.email, new_wallet.coin, new_wallet.address))
                wallet_row = cur.fetchone()
                conn.commit()
                
                return {
                    "id": str(wallet_row[0]),
                    "email": wallet_row[1],
                    "coin": wallet_row[2],
                    "address": wallet_row[3],
                    "balance": str(wallet_row[4]),
                    "is_active": wallet_row[5],
                    "created": wallet_row[6].isoformat() if wallet_row[6] else None,
                    "updated": wallet_row[7].isoformat() if wallet_row[7] else None
                }

    def create_bank_account(self, new_bank_account: NewBankAccount, user: User) -> dict:
        """Create a new bank account for user"""
        with self.get_connection() as conn:
            with conn.cursor() as cur:
                # Check if user already has a bank account
                cur.execute("SELECT id FROM bank_accounts WHERE email = %s", (user.email,))
                existing = cur.fetchone()
                if existing:
                    raise ValueError("User already has a bank account")
                
                cur.execute("""
                    INSERT INTO bank_accounts (email, account_name, account_number, branch_code)
                    VALUES (%s, %s, %s, %s)
                    RETURNING id, email, account_name, account_number, branch_code, created, updated
                """, (user.email, new_bank_account.accountName, new_bank_account.accountNumber, new_bank_account.branchCode))
                account_row = cur.fetchone()
                conn.commit()
                
                return {
                    "id": str(account_row[0]),
                    "email": account_row[1],
                    "account_name": account_row[2],
                    "account_number": account_row[3],
                    "branch_code": account_row[4],
                    "created": account_row[5].isoformat() if account_row[5] else None,
                    "updated": account_row[6].isoformat() if account_row[6] else None
                }

    def get_bank_accounts(self, user: User) -> List[dict]:
        """Get all bank accounts for user"""
        with self.get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT id, email, account_name, account_number, branch_code, created, updated
                    FROM bank_accounts 
                    WHERE email = %s
                """, (user.email,))
                accounts = cur.fetchall()
                
                result = []
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

    # Session management (in-memory for now)
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
            del self.sessions[session_token]
        return None

    def delete_session(self, session_token: str) -> bool:
        if session_token in self.sessions:
            del self.sessions[session_token]
            return True
        return False

    # Trade management (in-memory for now)
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

    def get_all_market_data(self) -> List[MarketData]:
        return self.latest_prices

# Create global storage instance
storage = PostgresStorage()