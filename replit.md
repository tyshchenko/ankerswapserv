# Cryptocurrency Trading Platform

## Overview
This is a Python-based cryptocurrency trading platform backend built with Tornado web framework. It integrates with the VALR cryptocurrency exchange API to provide real-time market data and trading functionality.

## Recent Changes
- **2025-09-10**: Project imported and configured for Replit environment
  - Migrated from MySQL to PostgreSQL database
  - Updated server configuration to run on port 8000
  - Created comprehensive PostgreSQL storage layer
  - Fixed code issues and import errors
  - Set up deployment configuration

## Project Architecture
- **Backend Framework**: Tornado (Python web framework)
- **Database**: PostgreSQL (Replit managed)
- **Authentication**: Session-based with Google OAuth support
- **External APIs**: VALR exchange API, CryptoCompare API
- **Features**: User management, wallet management, trading, real-time market data via WebSocket

## Key Files
- `server.py`: Main server application with API endpoints
- `postgres_storage.py`: PostgreSQL database layer
- `models.py`: Pydantic data models
- `auth_utils.py`: Authentication utilities
- `config.py`: Configuration management

## API Endpoints
- `/api/market`: Market data endpoints
- `/api/auth/*`: Authentication (register, login, logout, Google OAuth)
- `/api/trades`: Trading functionality
- `/api/wallets`: Wallet management
- `/ws`: WebSocket for real-time updates

## Environment Variables
- `DATABASE_URL`: PostgreSQL connection (automatically configured)
- `VALR_KEY`, `VALR_SECRET`: VALR API credentials (optional)
- `GOOGLE_CLIENT_ID`: Google OAuth client ID (optional)

## Development
- Server runs on port 8000
- Database tables are automatically created on startup
- Market data is fetched from external APIs with fallback to mock data
- Real-time updates via WebSocket

## Deployment
Configured for VM deployment on Replit with persistent database connection.