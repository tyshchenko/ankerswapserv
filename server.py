#!/usr/bin/env python3.9

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
import os
import asyncio
import tornado.web
import tornado.ioloop
import tornado.httpserver
import tornado.websocket
import json
import random
import threading
import requests
import numbers
import time
from typing import Optional, Set
from pydantic import ValidationError
from datetime import datetime, timedelta
from pathlib import Path
import telebot

from tornado.options import define, options

from auth_utils import auth_utils
from models import InsertTrade, InsertMarketData, LoginRequest, RegisterRequest, User, InsertUser, NewWallet, NewBankAccount

from config import GOOGLE_CLIENT_ID, DATABASE_TYPE

# Import storage based on configuration
if DATABASE_TYPE.lower() == 'mysql':
    from storage import storage
elif DATABASE_TYPE.lower() == 'postgresql':
    from postgres_storage import storage
else:
    # Default to PostgreSQL
    from postgres_storage import storage

class DateTimeEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, datetime):
            return obj.isoformat()
        elif isinstance(obj, (int, float)):
            return str(obj)
        else:
            return super().default(obj)
      
class Application(tornado.web.Application):
    coins = {}
    
    def __init__(self):
        print("%s start starting" % datetime.now())
        self.cache = {}
        threading.Timer(17.0, self.wathcher).start()
    

        handlers = [
            # API routes
            (r"/api/market/(.+)", MarketDataHandler),
            (r"/api/market", MarketDataHandler),
            (r"/api/trades", TradesHandler),
            (r"/api/trades/(.+)", UserTradesHandler),
            (r"/api/wallets", WalletsHandler),
            (r"/api/wallet/create", WalletCreateHandler),
            (r"/api/bankaccount/create", BankAccountCreateHandler),
            
            # Authentication routes
            (r"/api/auth/register", RegisterHandler),
            (r"/api/auth/login", LoginHandler),
            (r"/api/auth/logout", LogoutHandler),
            (r"/api/auth/google", GoogleAuthHandler),
            (r"/api/auth/me", MeHandler),
            
            # WebSocket route
            (r"/ws", WebSocketHandler),
            (r'/.*', NotFoundHandler)
        ]
    
        settings = {
            "cookie_secret": "sdfg54dfg54dh454hf654",
            "debug": True
        }
        super(Application, self).__init__(handlers, **settings)

    def wathcher(self):
        try:
          storage.update_latest_prices()
          print("\n %s \n" % datetime.now())
          print(str(float(str((random.random() - 0.5) * 5))))
        except Exception as e: print(e)
        threading.Timer(60.0, self.wathcher).start()



class BaseHandler(tornado.web.RequestHandler):
    def set_default_headers(self):
        self.set_header("Access-Control-Allow-Origin", "*")
        self.set_header("Access-Control-Allow-Headers", "x-requested-with")
        self.set_header('Access-Control-Allow-Methods', 'POST, GET, OPTIONS')
        self.set_header("Cache-Control", "no-cache")
        self.set_header("Content-Type", "application/json")

    def write_error(self, status_code, **kwargs):
        if status_code == 404:
            self.write({"error": "Resource not found. Check the URL."})
        elif status_code == 405:
            self.write({"error": "Method not allowed in this resource."})
        else:
            if "error_message" in kwargs:
                message = kwargs["error_message"]
            else:
                message = "Internal Server Error"
            self.write({"error": message})

    def write(self, chunk):
        if isinstance(chunk, dict):
            chunk = json.dumps(chunk, cls=DateTimeEncoder)
            self.set_header("Content-Type", "application/json; charset=UTF-8")
        super().write(chunk)
        
    def post(self):  # for all methods
        self.write({"code": 404,"msg": "Invalid API resource path."})
        
    def options(self):
        self.set_status(204)
        self.finish()

    def get_auth_headers(self):
        return self.application.get_auth_headers()

    def get_time(self, btc):
        ms = int(time.time())
        return str(ms)+"_"+btc
      
    def get_current_user_from_session(self) -> Optional[User]:
        """Get current user from session token"""
        session_token = self.get_secure_cookie("session_token")
        if not session_token:
            return None
        
        session_token = session_token.decode('utf-8')
        session = storage.get_session(session_token)
        if not session:
            return None
        
        return storage.get_user(session.user_id)
      

class NotFoundHandler(BaseHandler):
    def get(self):  # for all methods
        self.set_status(404)
        self.write({"error": "Invalid API resource path."})


class RegisterHandler(BaseHandler):
    def post(self):
        try:
            body = json.loads(self.request.body.decode())
            register_data = RegisterRequest(**body)
            
            # Check if user already exists
            existing_user = storage.get_user_by_email(register_data.email)
            if existing_user:
                self.set_status(400)
                self.write({"error": "User with this email already exists"})
                return

            # Hash password
            password_hash = auth_utils.hash_password(register_data.password)

            # Create user
            insert_user = InsertUser(
                email=register_data.email,
                password_hash=password_hash,
                first_name=register_data.first_name,
                last_name=register_data.last_name
            )

            user = storage.create_user(insert_user)

            # Create session
            session_token = auth_utils.generate_session_token()
            expires_at = datetime.now() + timedelta(days=7)
            storage.create_session(user.id, session_token, expires_at)

            # Set secure cookie
            self.set_secure_cookie("session_token", session_token, expires_days=7)

            # Return user data (without password)
            user_data = user.dict()
            user_data.pop('password_hash', None)
            
            self.write({
                "success": True,
                "user": user_data,
                "message": "User registered successfully"
            })
            
        except ValidationError as e:
            print(e)
            self.set_status(400)
            self.write({"error": "Invalid registration data", "details": e.errors()})
        except Exception as e:
            print(e)
            self.set_status(500)
            self.write({"error": str(e)})


class LoginHandler(BaseHandler):
    def post(self):
        try:
            body = json.loads(self.request.body.decode())
            login_data = LoginRequest(**body)
            
            # Find user by email
            user = storage.get_user_by_email(login_data.email)
            if not user or not user.password_hash:
                self.set_status(401)
                self.write({"error": "Invalid email or password"})
                return
            
            # Verify password
            if not auth_utils.verify_password(login_data.password, user.password_hash):
                self.set_status(401)
                self.write({"error": "Invalid email or password"})
                return
            
            # Create session
            session_token = auth_utils.generate_session_token()
            expires_at = datetime.now() + timedelta(days=7)
            storage.create_session(user.id, session_token, expires_at)
            
            # Set secure cookie
            self.set_secure_cookie("session_token", session_token, expires_days=7)
            
            # Return user data (without password)
            user_data = user.dict()
            user_data.pop('password_hash', None)
            
            self.write({
                "success": True,
                "user": user_data,
                "message": "Login successful"
            })
            
        except ValidationError as e:
            print(e)
            self.set_status(400)
            self.write({"error": "Invalid login data", "details": e.errors()})
        except Exception as e:
            print(e)
            self.set_status(500)
            self.write({"error": str(e)})


class LogoutHandler(BaseHandler):
    def post(self):
        try:
            session_token = self.get_secure_cookie("session_token")
            if session_token:
                session_token = session_token.decode('utf-8')
                storage.delete_session(session_token)
            
            # Clear cookie
            self.clear_cookie("session_token")
            
            self.write({
                "success": True,
                "message": "Logout successful"
            })
            
        except Exception as e:
            print(e)
            self.set_status(500)
            self.write({"error": str(e)})


class GoogleAuthHandler(BaseHandler):
    def post(self):
        try:
            body = json.loads(self.request.body.decode())
            google_token = body.get('token')
            
            if not google_token:
                self.set_status(400)
                self.write({"error": "Google token is required"})
                return
            
            # Get Google client ID from environment
            google_client_id = GOOGLE_CLIENT_ID
            if not google_client_id:
                self.set_status(500)
                self.write({"error": "Google authentication not configured"})
                return
            
            # Verify Google token
            google_user_info = auth_utils.verify_google_token(google_token, google_client_id)
            if not google_user_info:
                self.set_status(401)
                self.write({"error": "Invalid Google token"})
                return
            
            # Check if user exists by Google ID
            user = storage.get_user_by_google_id(google_user_info['google_id'])
            
            if not user:
                # Check if user exists by email
                user = storage.get_user_by_email(google_user_info['email'])
                
                if user:
                    # Update existing user with Google ID
                    user.google_id = google_user_info['google_id']
                    if not user.profile_image_url:
                        user.profile_image_url = google_user_info.get('profile_image_url')
                else:
                    # Create new user
                    insert_user = InsertUser(
                        email=google_user_info['email'],
                        google_id=google_user_info['google_id'],
                        first_name=google_user_info.get('first_name'),
                        last_name=google_user_info.get('last_name'),
                        profile_image_url=google_user_info.get('profile_image_url')
                    )
                    user = storage.create_user(insert_user)
            
            # Create session
            session_token = auth_utils.generate_session_token()
            expires_at = datetime.now() + timedelta(days=7)
            storage.create_session(user.id, session_token, expires_at)
            
            # Set secure cookie
            self.set_secure_cookie("session_token", session_token, expires_days=7)
            
            # Return user data
            user_data = user.dict()
            user_data.pop('password_hash', None)
            
            self.write({
                "success": True,
                "user": user_data,
                "message": "Google authentication successful"
            })
            
        except Exception as e:
            print(e)
            self.set_status(500)
            self.write({"error": str(e)})


class MeHandler(BaseHandler):
    def get(self):
        """Get current user information"""
        try:
            user = self.get_current_user_from_session()
            if not user:
                self.set_status(401)
                self.write({"error": "Not authenticated"})
                return
            
            # Return user data (without password)
            user_data = user.dict()
            user_data.pop('password_hash', None)
            
            self.write({
                "success": True,
                "user": user_data
            })
            
        except Exception as e:
            print(e)
            self.set_status(500)
            self.write({"error": str(e)})


class WalletsHandler(BaseHandler):
    def post(self):
        """Get user wallets with password_hash authentication"""
        try:
            body = json.loads(self.request.body.decode())
            user = self.get_current_user_from_session()
            if not user:
                self.set_status(401)
                self.write({"error": "Invalid authentication"})
                return
            
            # Get user wallets
            wallets = storage.get_wallets(user)
            
            # Format wallet data
            wallet_data = []
            if wallets:
                for wallet in wallets:
                    wallet_data.append({
                        "id": str(wallet[0]),
                        "email": wallet[1],
                        "coin": wallet[2],
                        "address": wallet[3],
                        "balance": str(wallet[4]),
                        "is_active": wallet[5],
                        "created": wallet[6].isoformat() if wallet[6] else None,
                        "updated": wallet[7].isoformat() if wallet[7] else None
                    })
            
            self.write({
                "success": True,
                "wallets": wallet_data
            })
            
        except Exception as e:
            print(e)
            self.set_status(500)
            self.write({"error": str(e)})


class WalletCreateHandler(BaseHandler):
    def post(self):
        """Create a new wallet for the authenticated user"""
        try:
            body = json.loads(self.request.body.decode())
            user = self.get_current_user_from_session()
            if not user:
                self.set_status(401)
                self.write({"error": "Authentication required"})
                return
            
            # Validate input data
            try:
                new_wallet_data = NewWallet(**body)
            except ValidationError as e:
                self.set_status(400)
                self.write({"error": "Invalid wallet data", "details": e.errors()})
                return
            
            # Check if wallet already exists for this coin
            existing_wallets = storage.get_wallets(user)
            for wallet in existing_wallets:
                if wallet[2] == new_wallet_data.coin:  # wallet[2] is the coin field
                    self.set_status(400)
                    self.write({"error": f"Wallet for {new_wallet_data.coin} already exists"})
                    return
            
            # Create the new wallet
            wallet = storage.create_wallet(new_wallet_data, user)
            
            self.write({
                "success": True,
                "wallet": wallet,
                "message": "Wallet created successfully"
            })
            
        except Exception as e:
            print(e)
            self.set_status(500)
            self.write({"error": str(e)})


class BankAccountCreateHandler(BaseHandler):
    def post(self):
        """Create a new bank account for the authenticated user"""
        try:
            body = json.loads(self.request.body.decode())
            user = self.get_current_user_from_session()
            if not user:
                self.set_status(401)
                self.write({"error": "Authentication required"})
                return
            
            # Validate input data
            try:
                new_bank_account_data = NewBankAccount(**body)
            except ValidationError as e:
                self.set_status(400)
                self.write({"error": "Invalid bank account data", "details": e.errors()})
                return
            
            # Create the new bank account
            try:
                bank_account = storage.create_bank_account(new_bank_account_data, user)
                
                self.write({
                    "success": True,
                    "bank_account": bank_account,
                    "message": "Bank account created successfully"
                })
            except ValueError as e:
                self.set_status(400)
                self.write({"error": str(e)})
                return
            
        except Exception as e:
            print(e)
            self.set_status(500)
            self.write({"error": str(e)})


class MarketDataHandler(BaseHandler):
    def get(self, pair: Optional[str] = None):
        try:
            if pair:
                print("Get specific pair data: /api/market/{pair}")
                data = storage.get_market_data(pair)
                self.write(json.dumps([item.dict(by_alias=True) for item in data], cls=DateTimeEncoder))
            else:
                print("Get all market data: /api/market")
                data = storage.get_all_market_data()
                #print(data)
                self.write(json.dumps([item.dict(by_alias=True) for item in data], cls=DateTimeEncoder))
        except Exception as e:
            print(e)
            self.set_status(500)
            self.write({"error": "Failed to fetch market data"})


class TradesHandler(BaseHandler):
    def post(self):
        try:
            body = json.loads(self.request.body.decode())
            trade_data = InsertTrade(**body)
            trade = storage.create_trade(trade_data)
            self.write(trade.dict(by_alias=True))
        except ValidationError as e:
            print(e)
            self.set_status(400)
            self.write({"error": "Invalid trade data", "details": e.errors()})
        except Exception as e:
            print(e)
            self.set_status(500)
            self.write({"error": str(e)})


class UserTradesHandler(BaseHandler):
    def get(self, user_id: str):
        try:
            trades = storage.get_user_trades(user_id)
            self.write({"data": [trade.dict(by_alias=True) for trade in trades]})
        except Exception as e:
            print(e)
            self.set_status(500)
            self.write({"error": "Failed to fetch trades"})


class WebSocketHandler(tornado.websocket.WebSocketHandler):
    clients: Set['WebSocketHandler'] = set()
    
    def check_origin(self, origin):
        return True  # Allow all origins for development
    
    def open(self, *args, **kwargs):
        self.clients.add(self)
        print("WebSocket client connected")
        # Send initial market data
        self.send_initial_data()
    
    def send_initial_data(self):
        try:
            data = storage.get_all_market_data()
            message = {
                "type": "market_data",
                "data": [item.dict(by_alias=True) for item in data]
            }
            self.write_message(json.dumps(message, cls=DateTimeEncoder))
        except Exception as e:
            print(e)
            print(f"Error sending initial data: {e}")
    
    def on_message(self, message):
        try:
            data = json.loads(message)
            if data.get("type") == "subscribe" and data.get("pair"):
                print(f"Client subscribed to {data['pair']}")
        except json.JSONDecodeError as e:
            print(f"Invalid WebSocket message received: {e}")
    
    def on_close(self):
        self.clients.discard(self)
        print("WebSocket client disconnected")
    
    @classmethod
    def broadcast_market_update(cls, data):
        """Broadcast market data updates to all connected clients"""
        if cls.clients:
            message = {
                "type": "market_data",
                "data": [item.dict(by_alias=True) for item in data]
            }
            message_str = json.dumps(message, cls=DateTimeEncoder)
            for client in cls.clients.copy():
                try:
                    client.write_message(message_str)
                except Exception as e:
                    print(e)
                    cls.clients.discard(client)

def main():
    tornado.options.parse_command_line()
    app = Application()
    app.listen(8000, address='0.0.0.0')
    #logging.getLogger('tornado.access').disabled = True
    tornado.ioloop.IOLoop.current().start()

if __name__ == "__main__":
    main()
