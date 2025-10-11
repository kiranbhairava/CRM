# database.py
# Separate database configuration to avoid circular imports

import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session
from dotenv import load_dotenv

load_dotenv()

# Configuration
DATABASE_URL = os.getenv("DATABASE_URL", "mysql+pymysql://user:password@localhost/edtech_crm")
EXTERNAL_DB_URL = os.getenv("EXTERNAL_DB_URL", "mysql+pymysql://user:password@external-host:3306/website_db")

# Main CRM Database Engine
engine = create_engine(
    DATABASE_URL,
    pool_pre_ping=True,
    pool_recycle=280
)

# Session maker for CRM database
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# External Website Database Engine
external_engine = create_engine(
    EXTERNAL_DB_URL,
    pool_pre_ping=True,
    pool_recycle=280
)

# Database dependency
def get_db():
    """Dependency for getting database session"""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()