# auth.py - Authentication Helpers
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session
from datetime import datetime, timedelta
import jwt
import os
from typing import Optional
from roles import User, UserRole, RoleManager, PermissionChecker

# Configuration
SECRET_KEY = os.getenv("SECRET_KEY", "your-secret-key-change-this")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 600

# Database dependency (you'll need to implement this based on your setup)
def get_db():
    """Database dependency - implement based on your database setup"""
    # This should yield a database session
    # Example:
    # db = SessionLocal()
    # try:
    #     yield db
    # finally:
    #     db.close()
    pass

security = HTTPBearer(auto_error=False)

# Token Management
class TokenManager:
    
    @staticmethod
    def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
        """Create JWT access token"""
        to_encode = data.copy()
        if expires_delta:
            expire = datetime.utcnow() + expires_delta
        else:
            expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        
        to_encode.update({"exp": expire})
        encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
        return encoded_jwt
    
    @staticmethod
    def verify_token(token: str) -> Optional[dict]:
        """Verify JWT token and return payload"""
        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
            return payload
        except jwt.PyJWTError:
            return None

# # Authentication Dependencies
# def get_current_user(
#     credentials: HTTPAuthorizationCredentials = Depends(security), 
#     db: Session = Depends(get_db)
# ) -> User:
#     """Get current authenticated user"""
#     if not credentials:
#         raise HTTPException(
#             status_code=status.HTTP_401_UNAUTHORIZED,
#             detail="Authorization header missing"
#         )
    
#     payload = TokenManager.verify_token(credentials.credentials)
#     if not payload:
#         raise HTTPException(
#             status_code=status.HTTP_401_UNAUTHORIZED,
#             detail="Invalid token"
#         )
    
#     email = payload.get("sub")
#     if not email:
#         raise HTTPException(
#             status_code=status.HTTP_401_UNAUTHORIZED,
#             detail="Invalid token payload"
#         )
    
#     user = RoleManager.get_user_by_email(db, email)
#     if not user:
#         raise HTTPException(
#             status_code=status.HTTP_401_UNAUTHORIZED,
#             detail="User not found"
#         )
    
#     if not user.is_active:
#         raise HTTPException(
#             status_code=status.HTTP_401_UNAUTHORIZED,
#             detail="User account is inactive"
#         )
    
#     return user

# def require_admin(current_user: User = Depends(get_current_user)) -> User:
#     """Require admin role"""
#     if not PermissionChecker.is_admin(current_user):
#         raise HTTPException(
#             status_code=status.HTTP_403_FORBIDDEN,
#             detail="Admin privileges required"
#         )
#     return current_user

# def require_sales_manager(current_user: User = Depends(get_current_user)) -> User:
#     """Require sales manager role"""
#     if not PermissionChecker.is_sales_manager(current_user):
#         raise HTTPException(
#             status_code=status.HTTP_403_FORBIDDEN,
#             detail="Sales manager privileges required"
#         )
#     return current_user

# def require_admin_or_sales_manager(current_user: User = Depends(get_current_user)) -> User:
#     """Require either admin or sales manager role"""
#     if not (PermissionChecker.is_admin(current_user) or PermissionChecker.is_sales_manager(current_user)):
#         raise HTTPException(
#             status_code=status.HTTP_403_FORBIDDEN,
#             detail="Admin or Sales Manager privileges required"
#         )
#     return current_user


# Lead Access Control
class LeadAccessControl:
    
    @staticmethod
    def can_access_lead(user: User, lead_id: int, db: Session) -> bool:
        """Check if user can access a specific lead"""
        if PermissionChecker.is_admin(user):
            return True  # Admin can access all leads
        
        # Sales managers can only access their assigned leads
        from models import Lead
        lead = db.query(Lead).filter(Lead.id == lead_id).first()
        if not lead:
            return False
        
        return lead.assigned_to == user.id
    
    @staticmethod
    def get_accessible_leads_query(user: User, db: Session):
        """Get query for leads that user can access"""
        from models import Lead
        
        if PermissionChecker.is_admin(user):
            # Admin can see all leads
            return db.query(Lead)
        else:
            # Sales managers can only see their assigned leads
            return db.query(Lead).filter(Lead.assigned_to == user.id)
    
    @staticmethod
    def can_assign_lead(user: User) -> bool:
        """Check if user can assign leads"""
        return PermissionChecker.is_admin(user)

# Activity Access Control
class ActivityAccessControl:
    
    @staticmethod
    def can_access_activity(user: User, activity_id: int, db: Session) -> bool:
        """Check if user can access a specific activity"""
        if PermissionChecker.is_admin(user):
            return True
        
        from models import Activity
        activity = db.query(Activity).filter(Activity.id == activity_id).first()
        if not activity:
            return False
        
        return activity.sales_manager_id == user.id
    
    @staticmethod
    def get_accessible_activities_query(user: User, db: Session):
        """Get query for activities that user can access"""
        from models import Activity
        
        if PermissionChecker.is_admin(user):
            return db.query(Activity)
        else:
            return db.query(Activity).filter(Activity.sales_manager_id == user.id)

# Deal Access Control
class DealAccessControl:
    
    @staticmethod
    def can_access_deal(user: User, deal_id: int, db: Session) -> bool:
        """Check if user can access a specific deal"""
        if PermissionChecker.is_admin(user):
            return True
        
        from models import Deal
        deal = db.query(Deal).filter(Deal.id == deal_id).first()
        if not deal:
            return False
        
        return deal.sales_manager_id == user.id
    
    @staticmethod
    def get_accessible_deals_query(user: User, db: Session):
        """Get query for deals that user can access"""
        from models import Deal
        
        if PermissionChecker.is_admin(user):
            return db.query(Deal)
        else:
            return db.query(Deal).filter(Deal.sales_manager_id == user.id)