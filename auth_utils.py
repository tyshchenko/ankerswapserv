import bcrypt
import jwt
import secrets
from datetime import datetime, timedelta
from typing import Optional
from google.auth.transport import requests
from google.oauth2 import id_token


class AuthUtils:
    def __init__(self, jwt_secret: Optional[str] = None):
        self.jwt_secret = jwt_secret or secrets.token_urlsafe(32)
    
    def hash_password(self, password: str) -> str:
        """Hash a password using bcrypt"""
        salt = bcrypt.gensalt()
        hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
        return hashed.decode('utf-8')
    
    def verify_password(self, password: str, hashed_password: str) -> bool:
        """Verify a password against its hash"""
        return bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8'))
    
    def generate_session_token(self) -> str:
        """Generate a secure session token"""
        return secrets.token_urlsafe(32)
    
    def create_jwt_token(self, user_id: str, expires_in_hours: int = 24) -> str:
        """Create a JWT token for the user"""
        payload = {
            'user_id': user_id,
            'exp': datetime.utcnow() + timedelta(hours=expires_in_hours),
            'iat': datetime.utcnow()
        }
        return jwt.encode(payload, self.jwt_secret, algorithm='HS256')
    
    def verify_jwt_token(self, token: str) -> Optional[dict]:
        """Verify and decode a JWT token"""
        try:
            payload = jwt.decode(token, self.jwt_secret, algorithms=['HS256'])
            return payload
        except jwt.ExpiredSignatureError:
            return None
        except jwt.InvalidTokenError:
            return None
    
    def verify_google_token(self, token: str, client_id: str) -> Optional[dict]:
        """Verify Google OAuth token and return user info"""
        try:
            # Verify the token
            idinfo = id_token.verify_oauth2_token(token, requests.Request(), client_id)
            
            # Verify the issuer
            if idinfo['iss'] not in ['accounts.google.com', 'https://accounts.google.com']:
                return None
            
            return {
                'google_id': idinfo['sub'],
                'email': idinfo.get('email'),
                'first_name': idinfo.get('given_name'),
                'last_name': idinfo.get('family_name'),
                'profile_image_url': idinfo.get('picture')
            }
        except ValueError:
            return None


# Global auth utils instance
auth_utils = AuthUtils()
