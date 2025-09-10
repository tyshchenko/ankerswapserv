from datetime import datetime
from typing import Optional, Literal
from pydantic import BaseModel, Field, EmailStr
import uuid


class User(BaseModel):
    id: Optional[str] = None
    email: Optional[str] = None
    username: Optional[str] = None
    reference: Optional[str] = None
    phone: Optional[str] = None
    country: Optional[str] = 'South Africa'
    language: Optional[str] = 'English'
    timezone: Optional[str] = 'Africa/Johannesburg'
    verification_level: Optional[str] = 'basic'
    phone: Optional[str] = None
    password_hash: Optional[str] = None
    google_id: Optional[str] = None
    first_name: Optional[str] = None
    second_names: Optional[str] = None
    last_name: Optional[str] = None
    profile_image_url: Optional[str] = None
    is_active: bool = True
    two_factor_enabled: bool = False
    email_notifications: bool = False
    sms_notifications: bool = False
    trading_notifications: bool = False
    security_alerts: bool = False
    created_at: datetime = Field(default_factory=datetime.now)
    updated_at: datetime = Field(default_factory=datetime.now)



class InsertUser(BaseModel):
    email: Optional[str] = None
    username: Optional[str] = None
    password: Optional[str] = None
    password_hash: Optional[str] = None
    google_id: Optional[str] = None
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    profile_image_url: Optional[str] = None


class LoginRequest(BaseModel):
    email: str
    password: str


class RegisterRequest(BaseModel):
    email: str
    password: str
    first_name: Optional[str] = None
    last_name: Optional[str] = None

class Wallet(BaseModel):
    email: str
    coin: str
    address: Optional[str] = None
    balance: str = "0"
    is_active: bool = True
    created_at: datetime = Field(default_factory=datetime.now)
    updated_at: datetime = Field(default_factory=datetime.now)

class NewWallet(BaseModel):
    coin: str
    address: Optional[str] = None

    
class BankAccount(BaseModel):
    email: str
    accountName: str = Field(..., alias="account_name")
    accountNumber: str = Field(..., alias="account_number")
    branchCode: str = Field(..., alias="branch_code")
    created_at: datetime = Field(default_factory=datetime.now)
    updated_at: datetime = Field(default_factory=datetime.now)


class NewBankAccount(BaseModel):
    accountName: str = Field(..., alias="account_name")
    accountNumber: str = Field(..., alias="account_number")
    branchCode: str = Field(..., alias="branch_code")

    model_config = {"populate_by_name": True}


class Session(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    user_id: str
    session_token: str
    expires_at: datetime
    created_at: datetime = Field(default_factory=datetime.now)


class Trade(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    userId: str = Field(..., alias="user_id")
    type: Literal["buy", "sell", "convert"]
    fromAsset: str = Field(..., alias="from_asset")
    toAsset: str = Field(..., alias="to_asset")
    fromAmount: float = Field(..., alias="from_amount")
    toAmount: float = Field(..., alias="to_amount")
    rate: float
    fee: float
    status: Literal["pending", "completed", "failed"] = "pending"
    createdAt: datetime = Field(default_factory=datetime.now, alias="created_at")

    model_config = {"populate_by_name": True}


class InsertTrade(BaseModel):
    userId: str = Field(..., alias="user_id")
    type: Literal["buy", "sell", "convert"]
    fromAsset: str = Field(..., alias="from_asset")
    toAsset: str = Field(..., alias="to_asset")
    fromAmount: float = Field(..., alias="from_amount")
    toAmount: float = Field(..., alias="to_amount")
    rate: float
    fee: float
    status: Literal["pending", "completed", "failed"] = "pending"

    model_config = {"populate_by_name": True}


class MarketData(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    pair: str
    price: str
    change24h: Optional[str] = Field(None, alias="change_24h")
    volume24h: Optional[str] = Field(None, alias="volume_24h")
    timestamp: datetime = Field(default_factory=datetime.now)

    model_config = {"populate_by_name": True}


class InsertMarketData(BaseModel):
    pair: str
    price: float
    change24h: Optional[float] = Field(None, alias="change_24h")
    volume24h: Optional[float] = Field(None, alias="volume_24h")

    model_config = {"populate_by_name": True}
