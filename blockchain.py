#!/usr/bin/env python3

import hashlib
import secrets
import base58
import requests
import threading
import time
from typing import Dict, List, Optional
from datetime import datetime
from ecdsa import SigningKey, SECP256k1
from ecdsa.util import string_to_number, number_to_string
from Crypto.Hash import keccak

class WalletGenerator:
    """Generate cryptocurrency wallets for different coins"""
    
    @staticmethod
    def generate_bitcoin_wallet():
        """Generate a Bitcoin wallet (private key, address)"""
        # Generate private key
        private_key = secrets.randbits(256)
        private_key_bytes = private_key.to_bytes(32, 'big')
        private_key_hex = private_key_bytes.hex()
        
        # Generate public key using ECDSA
        sk = SigningKey.from_string(private_key_bytes, curve=SECP256k1)
        vk = sk.get_verifying_key()
        public_key = b'\x04' + vk.to_string()
        
        # Generate Bitcoin address
        sha256_hash = hashlib.sha256(public_key).digest()
        ripemd160_hash = hashlib.new('ripemd160', sha256_hash).digest()
        
        # Add version byte (0x00 for mainnet)
        versioned_payload = b'\x00' + ripemd160_hash
        
        # Double SHA256 for checksum
        checksum = hashlib.sha256(hashlib.sha256(versioned_payload).digest()).digest()[:4]
        
        # Final address
        address_bytes = versioned_payload + checksum
        address = base58.b58encode(address_bytes).decode('utf-8')
        
        return {
            'private_key': private_key_hex,
            'address': address,
            'coin': 'BTC'
        }
    
    @staticmethod
    def generate_ethereum_wallet():
        """Generate an Ethereum wallet (private key, address)"""
        # Generate private key
        private_key = secrets.randbits(256)
        private_key_bytes = private_key.to_bytes(32, 'big')
        private_key_hex = private_key_bytes.hex()
        
        # Generate public key
        sk = SigningKey.from_string(private_key_bytes, curve=SECP256k1)
        vk = sk.get_verifying_key()
        public_key = vk.to_string()
        
        # Ethereum address is last 20 bytes of Keccak256 hash of public key
        keccak_hash = keccak.new(digest_bits=256)
        keccak_hash.update(public_key)
        address = '0x' + keccak_hash.hexdigest()[-40:]
        
        return {
            'private_key': private_key_hex,
            'address': address,
            'coin': 'ETH'
        }
    
    @staticmethod
    def generate_wallet(coin: str):
        """Generate wallet for specified coin"""
        coin = coin.upper()
        
        if coin in ['BTC', 'BITCOIN']:
            return WalletGenerator.generate_bitcoin_wallet()
        elif coin in ['ETH', 'ETHEREUM']:
            return WalletGenerator.generate_ethereum_wallet()
        elif coin in ['USDT', 'TETHER']:
            # USDT typically runs on Ethereum network
            wallet = WalletGenerator.generate_ethereum_wallet()
            wallet['coin'] = 'USDT'
            return wallet
        else:
            # Default to Bitcoin-like for other coins
            wallet = WalletGenerator.generate_bitcoin_wallet()
            wallet['coin'] = coin
            return wallet


class TransactionMonitor:
    """Monitor blockchain transactions for wallets"""
    
    def __init__(self):
        self.monitored_wallets: Dict[str, Dict] = {}
        self.monitoring_active = False
        self.monitor_thread = None
    
    def add_wallet(self, address: str, coin: str, user_email: str):
        """Add wallet to monitoring list"""
        self.monitored_wallets[address] = {
            'coin': coin,
            'user_email': user_email,
            'last_checked': datetime.now(),
            'balance': 0
        }
        
        # Start monitoring if not already active
        if not self.monitoring_active:
            self.start_monitoring()
    
    def remove_wallet(self, address: str):
        """Remove wallet from monitoring"""
        if address in self.monitored_wallets:
            del self.monitored_wallets[address]
    
    def start_monitoring(self):
        """Start the transaction monitoring thread"""
        if not self.monitoring_active:
            self.monitoring_active = True
            self.monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
            self.monitor_thread.start()
            print("Transaction monitoring started")
    
    def stop_monitoring(self):
        """Stop transaction monitoring"""
        self.monitoring_active = False
        if self.monitor_thread:
            self.monitor_thread.join()
        print("Transaction monitoring stopped")
    
    def _monitor_loop(self):
        """Main monitoring loop"""
        while self.monitoring_active:
            try:
                self._check_all_wallets()
                time.sleep(60)  # Check every minute
            except Exception as e:
                print(f"Error in monitoring loop: {e}")
                time.sleep(30)  # Wait 30 seconds on error
    
    def _check_all_wallets(self):
        """Check all monitored wallets for new transactions"""
        for address, wallet_info in self.monitored_wallets.items():
            try:
                self._check_wallet_transactions(address, wallet_info)
            except Exception as e:
                print(f"Error checking wallet {address}: {e}")
    
    def _check_wallet_transactions(self, address: str, wallet_info: Dict):
        """Check specific wallet for transactions"""
        coin = wallet_info['coin']
        
        if coin in ['BTC', 'BITCOIN']:
            self._check_bitcoin_transactions(address, wallet_info)
        elif coin in ['ETH', 'ETHEREUM', 'USDT']:
            self._check_ethereum_transactions(address, wallet_info)
        else:
            # For other coins, try Bitcoin-like API first
            self._check_bitcoin_transactions(address, wallet_info)
    
    def _check_bitcoin_transactions(self, address: str, wallet_info: Dict):
        """Check Bitcoin transactions using public API"""
        try:
            # Using a free Bitcoin API (BlockCypher)
            url = f"https://api.blockcypher.com/v1/btc/main/addrs/{address}/balance"
            response = requests.get(url, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                new_balance = data.get('balance', 0) / 100000000  # Convert satoshis to BTC
                
                if new_balance != wallet_info['balance']:
                    self._handle_balance_change(address, wallet_info, new_balance)
                    wallet_info['balance'] = new_balance
                
                wallet_info['last_checked'] = datetime.now()
        except Exception as e:
            print(f"Error checking Bitcoin address {address}: {e}")
    
    def _check_ethereum_transactions(self, address: str, wallet_info: Dict):
        """Check Ethereum transactions using public API"""
        try:
            # Note: This would typically require an API key for production use
            # For demo purposes, we'll simulate the check
            print(f"Checking Ethereum address {address} for {wallet_info['coin']}")
            wallet_info['last_checked'] = datetime.now()
        except Exception as e:
            print(f"Error checking Ethereum address {address}: {e}")
    
    def _handle_balance_change(self, address: str, wallet_info: Dict, new_balance: float):
        """Handle when a wallet balance changes"""
        old_balance = wallet_info['balance']
        difference = new_balance - old_balance
        
        if difference > 0:
            print(f"Incoming transaction detected!")
            print(f"Address: {address}")
            print(f"Coin: {wallet_info['coin']}")
            print(f"User: {wallet_info['user_email']}")
            print(f"Amount: +{difference}")
            
            # Here you could:
            # - Update database
            # - Send notification to user
            # - Trigger webhook
            # - Log to audit trail
    
    def get_wallet_status(self, address: str) -> Optional[Dict]:
        """Get current status of monitored wallet"""
        return self.monitored_wallets.get(address)
    
    def get_all_wallets(self) -> Dict[str, Dict]:
        """Get all monitored wallets"""
        return self.monitored_wallets.copy()


# Global instances
wallet_generator = WalletGenerator()
transaction_monitor = TransactionMonitor()


# Helper functions for easy import
def generate_wallet(coin: str):
    """Generate a new wallet for the specified coin"""
    return wallet_generator.generate_wallet(coin)


def start_monitoring_wallet(address: str, coin: str, user_email: str):
    """Start monitoring a wallet for transactions"""
    transaction_monitor.add_wallet(address, coin, user_email)


def stop_monitoring_wallet(address: str):
    """Stop monitoring a wallet"""
    transaction_monitor.remove_wallet(address)


def get_monitoring_status():
    """Get current monitoring status"""
    return {
        'active': transaction_monitor.monitoring_active,
        'wallets_count': len(transaction_monitor.monitored_wallets),
        'wallets': transaction_monitor.get_all_wallets()
    }