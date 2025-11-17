# # roles.py - Role Management System (Using werkzeug.security - No Password Length Issues)
# from sqlalchemy import Column, Enum, Integer, String, Boolean, DateTime, ForeignKey
# from sqlalchemy.orm import Session, relationship
# from sqlalchemy.ext.declarative import declarative_base
# from pydantic import BaseModel, EmailStr
# from werkzeug.security import generate_password_hash, check_password_hash
# from datetime import datetime
# from typing import Optional, List
# from enum import Enum as PyEnum
# from models import Lead, User  # make sure User is defined in models

# Base = declarative_base()

# # UserRole Enum
# class UserRole(str, PyEnum):
#     ADMIN = "ADMIN"
#     SALES_MANAGER = "SALES_MANAGER"
#     SALES_REP = "SALES_REP"

# # Pydantic Models (No password length validation needed with werkzeug)
# class UserCreate(BaseModel):
#     email: EmailStr
#     name: str
#     password: str
#     role: Optional[UserRole] = UserRole.SALES_MANAGER
#     monthly_target: Optional[int] = 0

# class UserLogin(BaseModel):
#     email: EmailStr
#     password: str

# class UserResponse(BaseModel):
#     id: int
#     name: str
#     email: str
#     role: UserRole
#     is_active: bool
#     monthly_target: int

# class SalesManagerCreate(BaseModel):
#     email: EmailStr
#     name: str
#     password: str
#     monthly_target: Optional[int] = 0

# # RoleManager (Using werkzeug.security - No password length issues)
# class RoleManager:

#     @staticmethod
#     def verify_password(plain_password: str, hashed_password: str) -> bool:
#         """Verify a password against its hash using werkzeug"""
#         return check_password_hash(hashed_password, plain_password)

#     @staticmethod
#     def get_password_hash(password: str) -> str:
#         """Generate password hash using werkzeug (no 72-byte limit)"""
#         return generate_password_hash(password)

#     @staticmethod
#     def create_admin(db: Session, admin_data: UserCreate) -> User:
#         """Create admin user"""
#         if db.query(User).filter(User.role == UserRole.ADMIN).first():
#             raise ValueError("Admin already exists")
#         if db.query(User).filter(User.email == admin_data.email).first():
#             raise ValueError("Email already registered")

#         hashed_password = RoleManager.get_password_hash(admin_data.password)
#         admin_user = User(
#             email=admin_data.email,
#             name=admin_data.name,
#             hashed_password=hashed_password,
#             role=UserRole.ADMIN,
#             monthly_target=0,
#             created_at=datetime.utcnow()
#         )
#         db.add(admin_user)
#         db.commit()
#         db.refresh(admin_user)
#         return admin_user

#     @staticmethod
#     def create_sales_manager(db: Session, sales_data: SalesManagerCreate, created_by: int) -> User:
#         creator = db.query(User).filter(User.id == created_by, User.role == UserRole.ADMIN).first()
#         if not creator:
#             raise ValueError("Only admin can create sales managers")
#         if db.query(User).filter(User.email == sales_data.email).first():
#             raise ValueError("Email already registered")

#         hashed_password = RoleManager.get_password_hash(sales_data.password)
#         sales_manager = User(
#             email=sales_data.email,
#             name=sales_data.name,
#             hashed_password=hashed_password,
#             role=UserRole.SALES_MANAGER,
#             monthly_target=sales_data.monthly_target,
#             admin_id=created_by,
#             created_by=created_by,
#             created_at=datetime.utcnow()
#         )
#         db.add(sales_manager)
#         db.commit()
#         db.refresh(sales_manager)
#         return sales_manager

#     @staticmethod
#     def authenticate_user(db: Session, email: str, password: str) -> Optional[User]:
#         user = db.query(User).filter(User.email == email).first()
#         if not user or not RoleManager.verify_password(password, user.hashed_password):
#             return None
#         return user

#     @staticmethod
#     def get_user_by_id(db: Session, user_id: int) -> Optional[User]:
#         return db.query(User).filter(User.id == user_id).first()

#     @staticmethod
#     def get_user_by_email(db: Session, email: str) -> Optional[User]:
#         return db.query(User).filter(User.email == email).first()

#     @staticmethod
#     def get_all_sales_managers(db: Session, admin_id: int) -> List[User]:
#         admin = db.query(User).filter(User.id == admin_id, User.role == UserRole.ADMIN).first()
#         if not admin:
#             raise ValueError("Only admin can view all sales managers")
#         return db.query(User).filter(User.role == UserRole.SALES_MANAGER).all()

#     @staticmethod
#     def deactivate_user(db: Session, user_id: int, admin_id: int) -> bool:
#         admin = db.query(User).filter(User.id == admin_id, User.role == UserRole.ADMIN).first()
#         if not admin:
#             raise ValueError("Only admin can deactivate users")
#         user = db.query(User).filter(User.id == user_id).first()
#         if not user or user.role == UserRole.ADMIN:
#             raise ValueError("Cannot deactivate this user")
#         user.is_active = False
#         db.commit()
#         return True

#     @staticmethod
#     def activate_user(db: Session, user_id: int, admin_id: int) -> bool:
#         admin = db.query(User).filter(User.id == admin_id, User.role == UserRole.ADMIN).first()
#         if not admin:
#             raise ValueError("Only admin can activate users")
#         user = db.query(User).filter(User.id == user_id).first()
#         if not user:
#             raise ValueError("User not found")
#         user.is_active = True
#         db.commit()
#         return True

# # Permission Checker
# class PermissionChecker:

#     @staticmethod
#     def is_admin(user: User) -> bool:
#         return user.role == UserRole.ADMIN

#     @staticmethod
#     def is_sales_manager(user: User) -> bool:
#         return user.role == UserRole.SALES_MANAGER

#     @staticmethod
#     def can_view_all_leads(user: User) -> bool:
#         return user.role == UserRole.ADMIN

#     @staticmethod
#     def can_assign_leads(user: User) -> bool:
#         return user.role == UserRole.ADMIN

#     @staticmethod
#     def can_create_users(user: User) -> bool:
#         return user.role == UserRole.ADMIN

#     @staticmethod
#     def can_view_all_analytics(user: User) -> bool:
#         return user.role == UserRole.ADMIN

#     @staticmethod
#     def can_manage_system_settings(user: User) -> bool:
#         return user.role == UserRole.ADMIN

# roles.py - Role Management System with Multiple Admin Support

from sqlalchemy import Column, Enum, Integer, String, Boolean, DateTime, ForeignKey
from sqlalchemy.orm import Session, relationship
from sqlalchemy.ext.declarative import declarative_base
from pydantic import BaseModel, EmailStr
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from typing import Optional, List
from enum import Enum as PyEnum
from models import Lead, User

Base = declarative_base()

# UserRole Enum
class UserRole(str, PyEnum):
    ADMIN = "ADMIN"
    SALES_MANAGER = "SALES_MANAGER"
    SALES_REP = "SALES_REP"

# Pydantic Models
class UserCreate(BaseModel):
    email: EmailStr
    name: str
    password: str
    role: Optional[UserRole] = UserRole.SALES_MANAGER
    monthly_target: Optional[int] = 0

class UserLogin(BaseModel):
    email: EmailStr
    password: str

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

# RoleManager with Multiple Admin Support
class RoleManager:

    @staticmethod
    def verify_password(plain_password: str, hashed_password: str) -> bool:
        """Verify a password against its hash using werkzeug"""
        return check_password_hash(hashed_password, plain_password)

    @staticmethod
    def get_password_hash(password: str) -> str:
        """Generate password hash using werkzeug"""
        return generate_password_hash(password)

    @staticmethod
    def create_admin(db: Session, admin_data: UserCreate, created_by: Optional[int] = None) -> User:
        """
        Create admin user with security checks
        
        Args:
            db: Database session
            admin_data: Admin user data
            created_by: ID of admin creating this admin (None for first admin only)
        
        Returns:
            Created User object
        
        Raises:
            ValueError: If security checks fail
        """
        # Count existing admins
        existing_admins = db.query(User).filter(User.role == UserRole.ADMIN).count()
        
        # If admins exist but no creator specified, reject
        if existing_admins > 0 and created_by is None:
            raise ValueError("Only existing admin can create new admins")
        
        # If admins exist and creator specified, verify creator is admin
        if existing_admins > 0 and created_by is not None:
            creator = db.query(User).filter(
                User.id == created_by, 
                User.role == UserRole.ADMIN
            ).first()
            if not creator or not creator.is_active:
                raise ValueError("Only active admins can create other admins")
        
        # Check email not already registered
        if db.query(User).filter(User.email == admin_data.email).first():
            raise ValueError("Email already registered")

        # Create admin
        hashed_password = RoleManager.get_password_hash(admin_data.password)
        admin_user = User(
            email=admin_data.email,
            name=admin_data.name,
            hashed_password=hashed_password,
            role=UserRole.ADMIN,
            monthly_target=0,
            created_by=created_by,  # Track who created this admin
            created_at=datetime.utcnow()
        )
        db.add(admin_user)
        db.commit()
        db.refresh(admin_user)
        return admin_user

    @staticmethod
    def create_sales_manager(db: Session, sales_data: SalesManagerCreate, created_by: int) -> User:
        """Create sales manager (Admin only)"""
        creator = db.query(User).filter(
            User.id == created_by, 
            User.role == UserRole.ADMIN
        ).first()
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
        """Authenticate user by email and password"""
        user = db.query(User).filter(User.email == email).first()
        if not user or not RoleManager.verify_password(password, user.hashed_password):
            return None
        return user

    @staticmethod
    def get_user_by_id(db: Session, user_id: int) -> Optional[User]:
        """Get user by ID"""
        return db.query(User).filter(User.id == user_id).first()

    @staticmethod
    def get_user_by_email(db: Session, email: str) -> Optional[User]:
        """Get user by email"""
        return db.query(User).filter(User.email == email).first()

    @staticmethod
    def get_all_sales_managers(db: Session, admin_id: int) -> List[User]:
        """Get all sales managers (Admin only)"""
        admin = db.query(User).filter(
            User.id == admin_id, 
            User.role == UserRole.ADMIN
        ).first()
        if not admin:
            raise ValueError("Only admin can view all sales managers")
        return db.query(User).filter(User.role == UserRole.SALES_MANAGER).all()

    @staticmethod
    def get_all_admins(db: Session, requesting_admin_id: int) -> List[User]:
        """Get all admins (Admin only)"""
        admin = db.query(User).filter(
            User.id == requesting_admin_id, 
            User.role == UserRole.ADMIN
        ).first()
        if not admin:
            raise ValueError("Only admin can view all admins")
        return db.query(User).filter(User.role == UserRole.ADMIN).all()

    @staticmethod
    def deactivate_user(db: Session, user_id: int, admin_id: int) -> bool:
        """Deactivate user (Admin only)"""
        admin = db.query(User).filter(
            User.id == admin_id, 
            User.role == UserRole.ADMIN
        ).first()
        if not admin:
            raise ValueError("Only admin can deactivate users")
        
        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            raise ValueError("User not found")
        
        # Prevent deactivating yourself
        if user.id == admin.id:
            raise ValueError("Cannot deactivate yourself")
        
        # Prevent deactivating last admin
        if user.role == UserRole.ADMIN:
            active_admins = db.query(User).filter(
                User.role == UserRole.ADMIN,
                User.is_active == True
            ).count()
            if active_admins <= 1:
                raise ValueError("Cannot deactivate the last active admin")
        
        user.is_active = False
        db.commit()
        return True

    @staticmethod
    def activate_user(db: Session, user_id: int, admin_id: int) -> bool:
        """Activate user (Admin only)"""
        admin = db.query(User).filter(
            User.id == admin_id, 
            User.role == UserRole.ADMIN
        ).first()
        if not admin:
            raise ValueError("Only admin can activate users")
        
        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            raise ValueError("User not found")
        
        user.is_active = True
        db.commit()
        return True

    @staticmethod
    def check_if_any_admin_exists(db: Session) -> bool:
        """Check if any admin exists in the system"""
        return db.query(User).filter(User.role == UserRole.ADMIN).count() > 0


# Permission Checker
class PermissionChecker:

    @staticmethod
    def is_admin(user: User) -> bool:
        """Check if user is admin"""
        return user.role == UserRole.ADMIN

    @staticmethod
    def is_sales_manager(user: User) -> bool:
        """Check if user is sales manager"""
        return user.role == UserRole.SALES_MANAGER

    @staticmethod
    def can_view_all_leads(user: User) -> bool:
        """Check if user can view all leads"""
        return user.role == UserRole.ADMIN

    @staticmethod
    def can_assign_leads(user: User) -> bool:
        """Check if user can assign leads"""
        return user.role == UserRole.ADMIN

    @staticmethod
    def can_create_users(user: User) -> bool:
        """Check if user can create users"""
        return user.role == UserRole.ADMIN

    @staticmethod
    def can_create_admins(user: User) -> bool:
        """Check if user can create admin accounts"""
        return user.role == UserRole.ADMIN and user.is_active

    @staticmethod
    def can_view_all_analytics(user: User) -> bool:
        """Check if user can view all analytics"""
        return user.role == UserRole.ADMIN

    @staticmethod
    def can_manage_system_settings(user: User) -> bool:
        """Check if user can manage system settings"""
        return user.role == UserRole.ADMIN