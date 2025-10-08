# roles.py - Role Management System (Fixed Password Length Issue)
from sqlalchemy import Column, Enum, Integer, String, Boolean, DateTime, ForeignKey
from sqlalchemy.orm import Session, relationship
from sqlalchemy.ext.declarative import declarative_base
from pydantic import BaseModel, EmailStr, validator
from passlib.context import CryptContext
from datetime import datetime
from typing import Optional, List
from enum import Enum as PyEnum
from models import Lead, User  # make sure User is defined in models

Base = declarative_base()

# Password hashing
pwd_context = CryptContext(
    schemes=["bcrypt_sha256", "bcrypt"],
    deprecated="auto"
)

# UserRole Enum
class UserRole(str, PyEnum):
    ADMIN = "ADMIN"
    SALES_MANAGER = "SALES_MANAGER"
    SALES_REP = "SALES_REP"

# Pydantic Models with password validation
class UserCreate(BaseModel):
    email: EmailStr
    name: str
    password: str
    role: Optional[UserRole] = UserRole.SALES_MANAGER
    monthly_target: Optional[int] = 0

    @validator('password')
    def validate_password_length(cls, v):
        # Convert to bytes and check length
        password_bytes = v.encode('utf-8')
        if len(password_bytes) > 72:
            # Truncate to 72 bytes
            truncated_bytes = password_bytes[:72]
            v = truncated_bytes.decode('utf-8', 'ignore')
        return v

class UserLogin(BaseModel):
    email: EmailStr
    password: str

    @validator('password')
    def validate_password_length(cls, v):
        # Convert to bytes and check length
        password_bytes = v.encode('utf-8')
        if len(password_bytes) > 72:
            # Truncate to 72 bytes
            truncated_bytes = password_bytes[:72]
            v = truncated_bytes.decode('utf-8', 'ignore')
        return v

class UserResponse(BaseModel):
    id: int
    name: str
    email: str
    role: UserRole
    is_active: bool
    monthly_target: int

class SalesManagerCreate(BaseModel):
    email: EmailStr
    name: str
    password: str
    monthly_target: Optional[int] = 0

    @validator('password')
    def validate_password_length(cls, v):
        # Convert to bytes and check length
        password_bytes = v.encode('utf-8')
        if len(password_bytes) > 72:
            # Truncate to 72 bytes
            truncated_bytes = password_bytes[:72]
            v = truncated_bytes.decode('utf-8', 'ignore')
        return v

# RoleManager (Fixed version)
class RoleManager:

    @staticmethod
    def verify_password(plain_password, hashed_password):
        # Ensure plain password doesn't exceed 72 bytes
        if isinstance(plain_password, str):
            password_bytes = plain_password.encode('utf-8')
            if len(password_bytes) > 72:
                plain_password = password_bytes[:72].decode('utf-8', 'ignore')
        return pwd_context.verify(plain_password, hashed_password)

    @staticmethod
    def get_password_hash(password: str) -> str:
        # Ensure password doesn't exceed 72 bytes before hashing
        if isinstance(password, str):
            password_bytes = password.encode('utf-8')
            if len(password_bytes) > 72:
                password = password_bytes[:72].decode('utf-8', 'ignore')
        return pwd_context.hash(password)

    @staticmethod
    def create_admin(db: Session, admin_data: UserCreate) -> User:
        """Create admin user"""
        if db.query(User).filter(User.role == UserRole.ADMIN).first():
            raise ValueError("Admin already exists")
        if db.query(User).filter(User.email == admin_data.email).first():
            raise ValueError("Email already registered")

        hashed_password = RoleManager.get_password_hash(admin_data.password)
        admin_user = User(
            email=admin_data.email,
            name=admin_data.name,
            hashed_password=hashed_password,
            role=UserRole.ADMIN,
            monthly_target=0,
            created_at=datetime.utcnow()
        )
        db.add(admin_user)
        db.commit()
        db.refresh(admin_user)
        return admin_user

    @staticmethod
    def create_sales_manager(db: Session, sales_data: SalesManagerCreate, created_by: int) -> User:
        creator = db.query(User).filter(User.id == created_by, User.role == UserRole.ADMIN).first()
        if not creator:
            raise ValueError("Only admin can create sales managers")
        if db.query(User).filter(User.email == sales_data.email).first():
            raise ValueError("Email already registered")

        hashed_password = RoleManager.get_password_hash(sales_data.password)
        sales_manager = User(
            email=sales_data.email,
            name=sales_data.name,
            hashed_password=hashed_password,
            role=UserRole.SALES_MANAGER,
            monthly_target=sales_data.monthly_target,
            admin_id=created_by,
            created_by=created_by,
            created_at=datetime.utcnow()
        )
        db.add(sales_manager)
        db.commit()
        db.refresh(sales_manager)
        return sales_manager

    @staticmethod
    def authenticate_user(db: Session, email: str, password: str) -> Optional[User]:
        user = db.query(User).filter(User.email == email).first()
        if not user or not RoleManager.verify_password(password, user.hashed_password):
            return None
        # Auto-upgrade hash if outdated
        if pwd_context.needs_update(user.hashed_password):
            user.hashed_password = RoleManager.get_password_hash(password)
            db.add(user)
            db.commit()
            db.refresh(user)
        return user

    @staticmethod
    def get_user_by_id(db: Session, user_id: int) -> Optional[User]:
        return db.query(User).filter(User.id == user_id).first()

    @staticmethod
    def get_user_by_email(db: Session, email: str) -> Optional[User]:
        return db.query(User).filter(User.email == email).first()

    @staticmethod
    def get_all_sales_managers(db: Session, admin_id: int) -> List[User]:
        admin = db.query(User).filter(User.id == admin_id, User.role == UserRole.ADMIN).first()
        if not admin:
            raise ValueError("Only admin can view all sales managers")
        return db.query(User).filter(User.role == UserRole.SALES_MANAGER).all()

    @staticmethod
    def deactivate_user(db: Session, user_id: int, admin_id: int) -> bool:
        admin = db.query(User).filter(User.id == admin_id, User.role == UserRole.ADMIN).first()
        if not admin:
            raise ValueError("Only admin can deactivate users")
        user = db.query(User).filter(User.id == user_id).first()
        if not user or user.role == UserRole.ADMIN:
            raise ValueError("Cannot deactivate this user")
        user.is_active = False
        db.commit()
        return True

    @staticmethod
    def activate_user(db: Session, user_id: int, admin_id: int) -> bool:
        admin = db.query(User).filter(User.id == admin_id, User.role == UserRole.ADMIN).first()
        if not admin:
            raise ValueError("Only admin can activate users")
        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            raise ValueError("User not found")
        user.is_active = True
        db.commit()
        return True

# Permission Checker (unchanged)
class PermissionChecker:

    @staticmethod
    def is_admin(user: User) -> bool:
        return user.role == UserRole.ADMIN

    @staticmethod
    def is_sales_manager(user: User) -> bool:
        return user.role == UserRole.SALES_MANAGER

    @staticmethod
    def can_view_all_leads(user: User) -> bool:
        return user.role == UserRole.ADMIN

    @staticmethod
    def can_assign_leads(user: User) -> bool:
        return user.role == UserRole.ADMIN

    @staticmethod
    def can_create_users(user: User) -> bool:
        return user.role == UserRole.ADMIN

    @staticmethod
    def can_view_all_analytics(user: User) -> bool:
        return user.role == UserRole.ADMIN

    @staticmethod
    def can_manage_system_settings(user: User) -> bool:
        return user.role == UserRole.ADMIN