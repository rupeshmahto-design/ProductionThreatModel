"""
Database configuration and session management
"""

import os
from typing import Generator

from dotenv import load_dotenv
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.pool import StaticPool

# Load environment variables from .env before building the engine
load_dotenv()

# Get database URL from environment
DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "sqlite:///./threat_modeling.db",
)

# Clean up DATABASE_URL if it has psql command prefix (common Render/Neon copy-paste error)
if DATABASE_URL:
    # Remove 'psql ' prefix if present
    if DATABASE_URL.startswith("psql "):
        DATABASE_URL = DATABASE_URL[5:].strip()
    
    # Remove surrounding quotes if present
    DATABASE_URL = DATABASE_URL.strip("'\"")
    
    # Handle postgresql+psycopg2:// conversion
    if DATABASE_URL.startswith("postgres://"):
        DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

# Create engine with special handling for SQLite
if DATABASE_URL.startswith("sqlite"):
    engine = create_engine(
        DATABASE_URL,
        echo=False,
        connect_args={"check_same_thread": False},
        poolclass=StaticPool
    )
else:
    engine = create_engine(
        DATABASE_URL,
        echo=False,
        pool_pre_ping=True,
        pool_size=10,
        max_overflow=20
    )

# Create session factory
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def get_db() -> Generator[Session, None, None]:
    """
    Dependency function for FastAPI to get database session.
    Automatically handles session lifecycle.
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db():
    """Initialize database tables"""
    from models import Base
    Base.metadata.create_all(bind=engine)


def reset_db():
    """Drop all tables and recreate (USE WITH CAUTION!)"""
    from models import Base
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
