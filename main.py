# main.py - EdTech CRM using existing modules
# from django import db
from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session
from datetime import datetime
import os
from dotenv import load_dotenv
import base64, json
from timeline_helper import TimelineLogger

# Import from our existing modules
from roles import User, UserRole, UserCreate, UserLogin, SalesManagerCreate, RoleManager, PermissionChecker, Base as RoleBase
from models import Lead, LeadCreate, LeadUpdate, LeadSource, LeadStatus, FileAttachment, ActionTimeline
from google_integration import GoogleWorkspaceManager, CalendarManager, GmailManager
from models import GoogleToken, Communication
import json
load_dotenv()
from external_website_leads_sync import router as external_leads_router
from database import engine, SessionLocal, get_db


# Configuration
DATABASE_URL = os.getenv("DATABASE_URL", "mysql+pymysql://user:password@localhost/edtech_crm")

# Database setup
# engine = create_engine(DATABASE_URL)
from sqlalchemy import create_engine

engine = create_engine(
    DATABASE_URL,
    pool_pre_ping=True,
    pool_recycle=280
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Create all tables
def create_tables():
    """Create all database tables if they don't exist"""
    try:
        print("Creating database tables if they don't exist...")
        
        # Import all models to ensure they are registered with Base
        from roles import Base as RoleBase
        from models import Base as ModelBase
        # from models import Base as ModelBase
        # from google_integration import Base as GoogleBase
        
        # Since all models use the same Base from roles, we can use RoleBase
        ModelBase.metadata.create_all(bind=engine)
        print("Database tables created successfully!")
        
        # Check if tables exist
        from sqlalchemy import inspect
        inspector = inspect(engine)
        tables = inspector.get_table_names()
        print(f"Available tables: {tables}")
        
    except Exception as e:
        print(f"Error creating tables: {str(e)}")
        raise

# FastAPI app
app = FastAPI(title="EdTech CRM - Adult Learners", version="1.0.0")

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Database dependency
# def get_db():
#     db = SessionLocal()
#     try:
#         yield db
#     finally:
#         db.close()

# Create tables on startup
@app.on_event("startup")
def on_startup():
    create_tables()

app.include_router(external_leads_router)

# Simple auth helpers (without circular imports)
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import jwt

SECRET_KEY = os.getenv("SECRET_KEY", "your-secret-key-change-this")
ALGORITHM = "HS256"
security = HTTPBearer(auto_error=False)

def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security), db: Session = Depends(get_db)):
    if not credentials:
        raise HTTPException(status_code=401, detail="No token")
    
    try:
        payload = jwt.decode(credentials.credentials, SECRET_KEY, algorithms=[ALGORITHM])
        email = payload.get("sub")
        if not email:
            raise HTTPException(status_code=401, detail="Invalid token")
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid token")
    
    user = RoleManager.get_user_by_email(db, email)
    if not user or not user.is_active:
        raise HTTPException(status_code=401, detail="User not found or inactive")
    
    return user

def require_admin(current_user: User = Depends(get_current_user)):
    if not PermissionChecker.is_admin(current_user):
        raise HTTPException(status_code=403, detail="Admin required")
    return current_user

# Import TokenManager after defining dependencies
from auth import TokenManager

# ================ ENDPOINTS ================

@app.get("/")
async def root():
    return {"message": "EdTech CRM API", "status": "running"}

@app.get("/test-db")
async def test_db(db: Session = Depends(get_db)):
    """Test database connection"""
    try:
        count = db.query(User).count()
        users = db.query(User).all()
        return {
            "status": "success", 
            "user_count": count,
            "users": [{"id": u.id, "name": u.name, "email": u.email, "role": u.role} for u in users]
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")

@app.post("/register")
async def register_admin(user_data: UserCreate, db: Session = Depends(get_db)):
    """Register first admin user"""
    try:
        admin = RoleManager.create_admin(db, user_data)
        return {"message": "Admin created successfully", "user_id": admin.id}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.post("/login")
async def login(login_data: UserLogin, db: Session = Depends(get_db)):
    """Login endpoint"""
    user = RoleManager.authenticate_user(db, login_data.email, login_data.password)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    access_token = TokenManager.create_access_token(data={"sub": user.email})
    
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "user": {
            "id": user.id,
            "name": user.name,
            "email": user.email,
            "role": user.role,
            "monthly_target": user.monthly_target
        }
    }

@app.get("/me")
async def get_me(current_user: User = Depends(get_current_user)):
    """Get current user info"""
    return {
        "id": current_user.id,
        "name": current_user.name,
        "email": current_user.email,
        "role": current_user.role,
        "monthly_target": current_user.monthly_target,
        "is_active": current_user.is_active
    }

# ============================================
# TIMELINE ENDPOINTS - Add these to main.py
# ============================================

from typing import Optional, List
from pydantic import BaseModel
from datetime import datetime, timedelta

class TimelineFilter(BaseModel):
    """Filter parameters for timeline"""
    entity_type: Optional[str] = None  # 'lead', 'communication', 'user'
    entity_id: Optional[int] = None
    action_type: Optional[str] = None  # 'CREATE', 'UPDATE', 'DELETE', etc.
    user_id: Optional[int] = None
    start_date: Optional[datetime] = None
    end_date: Optional[datetime] = None
    limit: Optional[int] = 50

class TimelineResponse(BaseModel):
    """Response model for timeline entries"""
    id: int
    user_id: int
    user_name: str
    action_type: str
    entity_type: str
    entity_id: int
    description: str
    details: Optional[dict] = None
    created_at: datetime

@app.get("/timeline")
async def get_timeline(
    entity_type: Optional[str] = None,
    entity_id: Optional[int] = None,
    action_type: Optional[str] = None,
    user_id: Optional[int] = None,
    days: Optional[int] = 30,
    limit: int = 50,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Get timeline of all actions
    Admins see everything, Sales Managers see only their actions
    """
    try:
        query = db.query(ActionTimeline)
        
        # Filter by date range (last N days)
        if days:
            start_date = datetime.utcnow() - timedelta(days=days)
            query = query.filter(ActionTimeline.created_at >= start_date)
        
        # Filter by entity type (lead, communication, user, etc.)
        if entity_type:
            query = query.filter(ActionTimeline.entity_type == entity_type)
        
        # Filter by specific entity
        if entity_id:
            query = query.filter(ActionTimeline.entity_id == entity_id)
        
        # Filter by action type (CREATE, UPDATE, DELETE, etc.)
        if action_type:
            query = query.filter(ActionTimeline.action_type == action_type)
        
        # Filter by user (who performed the action)
        if user_id:
            query = query.filter(ActionTimeline.user_id == user_id)
        
        # Role-based filtering
        if not PermissionChecker.is_admin(current_user):
            # Sales managers only see their own actions and actions on their leads
            query = query.filter(ActionTimeline.user_id == current_user.id)
        
        # Order by most recent first
        query = query.order_by(ActionTimeline.created_at.desc())
        
        # Limit results
        timeline_entries = query.limit(limit).all()
        
        return [{
            'id': entry.id,
            'user_id': entry.user_id,
            'user_name': entry.user_name,
            'action_type': entry.action_type,
            'entity_type': entry.entity_type,
            'entity_id': entry.entity_id,
            'description': entry.description,
            'details': entry.details,
            'created_at': entry.created_at
        } for entry in timeline_entries]
        
    except Exception as e:
        print(f"Error fetching timeline: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to fetch timeline: {str(e)}")

@app.get("/timeline/lead/{lead_id}")
async def get_lead_timeline(
    lead_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get timeline for a specific lead"""
    try:
        # Verify lead exists and user has access
        lead = db.query(Lead).filter(Lead.id == lead_id).first()
        if not lead:
            raise HTTPException(status_code=404, detail="Lead not found")
        
        # Check permissions
        if not PermissionChecker.is_admin(current_user) and lead.assigned_to != current_user.id:
            raise HTTPException(status_code=403, detail="You don't have access to this lead's timeline")
        
        # Get all timeline entries for this lead
        timeline_entries = db.query(ActionTimeline).filter(
            ActionTimeline.entity_type == 'lead',
            ActionTimeline.entity_id == lead_id
        ).order_by(ActionTimeline.created_at.desc()).all()
        
        return [{
            'id': entry.id,
            'user_id': entry.user_id,
            'user_name': entry.user_name,
            'action_type': entry.action_type,
            'entity_type': entry.entity_type,
            'entity_id': entry.entity_id,
            'description': entry.description,
            'details': entry.details,
            'created_at': entry.created_at
        } for entry in timeline_entries]
        
    except HTTPException:
        raise
    except Exception as e:
        print(f"Error fetching lead timeline: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to fetch lead timeline: {str(e)}")

@app.get("/timeline/stats")
async def get_timeline_stats(
    days: int = 7,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get timeline statistics"""
    try:
        start_date = datetime.utcnow() - timedelta(days=days)
        
        query = db.query(ActionTimeline).filter(ActionTimeline.created_at >= start_date)
        
        # Filter for sales managers
        if not PermissionChecker.is_admin(current_user):
            query = query.filter(ActionTimeline.user_id == current_user.id)
        
        all_entries = query.all()
        
        # Calculate stats
        stats = {
            'total_actions': len(all_entries),
            'by_action_type': {},
            'by_entity_type': {},
            'by_day': {},
            'most_active_users': {}
        }
        
        for entry in all_entries:
            # Count by action type
            stats['by_action_type'][entry.action_type] = stats['by_action_type'].get(entry.action_type, 0) + 1
            
            # Count by entity type
            stats['by_entity_type'][entry.entity_type] = stats['by_entity_type'].get(entry.entity_type, 0) + 1
            
            # Count by day
            day_key = entry.created_at.strftime('%Y-%m-%d')
            stats['by_day'][day_key] = stats['by_day'].get(day_key, 0) + 1
            
            # Count by user
            stats['most_active_users'][entry.user_name] = stats['most_active_users'].get(entry.user_name, 0) + 1
        
        # Sort most active users
        stats['most_active_users'] = dict(sorted(
            stats['most_active_users'].items(), 
            key=lambda x: x[1], 
            reverse=True
        )[:10])
        
        return stats
        
    except Exception as e:
        print(f"Error fetching timeline stats: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to fetch timeline stats: {str(e)}")

@app.post("/sales-managers")
async def create_sales_manager(
    sales_data: SalesManagerCreate, 
    current_user: User = Depends(require_admin), 
    db: Session = Depends(get_db)
):
    """Create sales manager (Admin only)"""
    try:
        sales_manager = RoleManager.create_sales_manager(db, sales_data, current_user.id)

        TimelineLogger.log_user_created(db, current_user, sales_manager)

        return {
            "message": f"Sales manager {sales_manager.name} created successfully",
            "user_id": sales_manager.id
        }
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.get("/sales-managers")
async def get_sales_managers(current_user: User = Depends(require_admin), db: Session = Depends(get_db)):
    """Get all sales managers (Admin only)"""
    try:
        sales_managers = RoleManager.get_all_sales_managers(db, current_user.id)
        return [{
            "id": sm.id,
            "name": sm.name,
            "email": sm.email,
            "is_active": sm.is_active,
            "monthly_target": sm.monthly_target
        } for sm in sales_managers]
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.put("/sales-managers/{user_id}")
async def update_sales_manager(
    user_id: int,
    update_data: dict,
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db)
):
    """Update sales manager details (Admin only)"""
    try:
        manager = db.query(User).filter(
            User.id == user_id,
            User.role == UserRole.SALES_MANAGER
        ).first()
        
        if not manager:
            raise HTTPException(status_code=404, detail="Sales manager not found")
        
        # ✅ FIXED: Track changes
        changed_fields = {}
        
        if 'name' in update_data and update_data['name'] != manager.name:
            changed_fields['name'] = {"old": manager.name, "new": update_data['name']}
            manager.name = update_data['name']
            
        if 'email' in update_data:
            existing = db.query(User).filter(
                User.email == update_data['email'],
                User.id != user_id
            ).first()
            if existing:
                raise HTTPException(status_code=400, detail="Email already in use")
            if update_data['email'] != manager.email:
                changed_fields['email'] = {"old": manager.email, "new": update_data['email']}
                manager.email = update_data['email']
                
        if 'monthly_target' in update_data and update_data['monthly_target'] != manager.monthly_target:
            changed_fields['monthly_target'] = {"old": manager.monthly_target, "new": update_data['monthly_target']}
            manager.monthly_target = update_data['monthly_target']
        
        if changed_fields:
            db.commit()
            db.refresh(manager)
            
            # ✅ ADD: Timeline logging
            TimelineLogger.log_user_updated(db, current_user, manager, changed_fields)
        
        return {
            "message": "Sales manager updated successfully",
            "manager": {
                "id": manager.id,
                "name": manager.name,
                "email": manager.email,
                "monthly_target": manager.monthly_target
            }
        }
    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=str(e))

# @app.delete("/sales-managers/{user_id}")
# async def delete_sales_manager(
#     user_id: int,
#     current_user: User = Depends(require_admin),
#     db: Session = Depends(get_db)
# ):
#     """Delete sales manager (Admin only)"""
#     try:
#         manager = db.query(User).filter(
#             User.id == user_id,
#             User.role == UserRole.SALES_MANAGER
#         ).first()
        
#         if not manager:
#             raise HTTPException(status_code=404, detail="Sales manager not found")
        
#         # Check if manager has assigned leads
#         assigned_leads = db.query(Lead).filter(Lead.assigned_to == user_id).count()
#         if assigned_leads > 0:
#             raise HTTPException(
#                 status_code=400, 
#                 detail=f"Cannot delete manager with {assigned_leads} assigned leads. Please reassign them first."
#             )
        
#         db.delete(manager)
#         db.commit()
        
#         return {"message": "Sales manager deleted successfully"}
#     except HTTPException:
#         raise
#     except Exception as e:
#         db.rollback()
#         raise HTTPException(status_code=500, detail=str(e))
@app.delete("/sales-managers/{user_id}")
async def delete_sales_manager(
    user_id: int,
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db)
):
    """Delete sales manager (Admin only)"""
    try:
        manager = db.query(User).filter(
            User.id == user_id,
            User.role == UserRole.SALES_MANAGER
        ).first()
        
        if not manager:
            raise HTTPException(status_code=404, detail="Sales manager not found")
        
        assigned_leads = db.query(Lead).filter(Lead.assigned_to == user_id).count()
        if assigned_leads > 0:
            raise HTTPException(
                status_code=400, 
                detail=f"Cannot delete manager with {assigned_leads} assigned leads"
            )
        
        # ✅ FIXED: Store data BEFORE deletion
        manager_name = manager.name
        
        db.delete(manager)
        db.commit()
        
        # ✅ ADD: Timeline logging
        TimelineLogger.log_user_deleted(db, current_user, user_id, manager_name)
        
        return {"message": "Sales manager deleted successfully"}
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=str(e))
    
# @app.get("/leads/{id}")
# async def get_lead(id: int, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
#     """Get lead details"""
#     lead = db.query(Lead).filter(Lead.id == id).first()
#     if not lead:
#         raise HTTPException(status_code=404, detail="Lead not found")
#     return lead

# @app.put("/leads/{id}")
# async def update_lead(id: int, lead_data: LeadUpdate, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
#     """Update lead details"""
#     lead = db.query(Lead).filter(Lead.id == id).first()
#     if not lead:
#         raise HTTPException(status_code=404, detail="Lead not found")

#     for key, value in lead_data.dict().items():
#         setattr(lead, key, value)

#     db.commit()
#     db.refresh(lead)
#     return lead

# @app.get("/dashboard")
# async def get_dashboard(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
#     """Get role-specific dashboard"""
#     if PermissionChecker.is_admin(current_user):
#         # Admin dashboard
#         total_users = db.query(User).count()
#         sales_managers = db.query(User).filter(User.role == UserRole.SALES_MANAGER).count()
#         leads = db.query(Lead).count()
        
#         return {
#             "role": "admin",
#             "total_users": total_users,
#             "sales_managers": sales_managers,
#             "leads": leads,
#             "message": f"Welcome Admin {current_user.name}"
#         }
#     else:
#         # Sales manager dashboard
#         return {
#             "role": "sales_manager",
#             "name": current_user.name,
#             "monthly_target": current_user.monthly_target,
#             "leads_assigned": db.query(Lead).filter(Lead.assigned_to == current_user.id).count(),
#             "leads_converted": db.query(Lead).filter(Lead.assigned_to == current_user.id, Lead.status == "Converted").count(),
#             "leads_in_progress": db.query(Lead).filter(Lead.assigned_to == current_user.id, Lead.status == "In Progress").count(),
#             "leads_new": db.query(Lead).filter(Lead.assigned_to == current_user.id, Lead.status == "New").count(),
#             "leads_lost": db.query(Lead).filter(Lead.assigned_to == current_user.id, Lead.status == "Lost").count(),
#             "message": f"Welcome {current_user.name}"
#         }

# ============================================
# ADD THIS TO main.py
# Place it after the existing /leads/{lead_id}/communications endpoint
# ============================================

from pydantic import BaseModel
from typing import Optional
from datetime import datetime

# Pydantic model for creating communications (including call logs)
class CommunicationCreate(BaseModel):
    type: str  # 'call', 'email', 'meeting', 'note'
    subject: str
    content: Optional[str] = None
    scheduled_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    status: Optional[str] = 'pending'
    call_type: Optional[str] = None  # 'Inbound' or 'Outbound'
    call_duration: Optional[int] = None  # in minutes
    lead_status: Optional[str] = None  # New lead status after call
    feedback: Optional[str] = None 

@app.post("/leads/{lead_id}/communications")
async def create_communication(
    lead_id: int,
    comm_data: CommunicationCreate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Create a new communication record (call log, email, meeting, note)"""
    try:
        # Verify lead exists
        lead = db.query(Lead).filter(Lead.id == lead_id).first()
        if not lead:
            raise HTTPException(status_code=404, detail="Lead not found")
        
        # Create communication record
        new_comm = Communication(
            lead_id=lead_id,
            user_id=current_user.id,
            type=comm_data.type,
            subject=comm_data.subject,
            content=comm_data.content,
            scheduled_at=comm_data.scheduled_at,
            completed_at=comm_data.completed_at,
            status=comm_data.status or 'pending',
            feedback=comm_data.feedback,
            created_at=datetime.utcnow()
        )
        
        db.add(new_comm)
        db.commit()
        db.refresh(new_comm)

        # Log timeline action
        lead_name = f"{lead.first_name} {lead.last_name}"
        TimelineLogger.log_communication_created(db, current_user, new_comm, lead_name)  

        return {
            'id': new_comm.id,
            'lead_id': new_comm.lead_id,
            'type': new_comm.type,
            'subject': new_comm.subject,
            'content': new_comm.content,
            'scheduled_at': new_comm.scheduled_at,
            'completed_at': new_comm.completed_at,
            'status': new_comm.status,
            'feedback': new_comm.feedback,
            'created_at': new_comm.created_at,
            'message': f'{comm_data.type.capitalize()} logged successfully'
        }
        
    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        print(f"Error creating communication: {str(e)}")
        import traceback
        traceback.print_exc()
        raise HTTPException(
            status_code=500, 
            detail=f"Failed to create communication: {str(e)}"
        )

# Optional: Get call logs specifically
@app.get("/leads/{lead_id}/calls")
async def get_lead_calls(
    lead_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get all call logs for a specific lead"""
    calls = db.query(Communication).filter(
        Communication.lead_id == lead_id,
        Communication.type == 'call'
    ).order_by(Communication.scheduled_at.desc()).all()
    
    return [{
        'id': c.id,
        'subject': c.subject,
        'content': c.content,
        'scheduled_at': c.scheduled_at,
        'completed_at': c.completed_at,
        'status': c.status,
        'created_at': c.created_at
    } for c in calls]

# Optional: Get call statistics for a lead
@app.get("/leads/{lead_id}/call-stats")
async def get_lead_call_stats(
    lead_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get call statistics for a specific lead"""
    try:
        calls = db.query(Communication).filter(
            Communication.lead_id == lead_id,
            Communication.type == 'call'
        ).all()
        
        total_calls = len(calls)
        held_calls = len([c for c in calls if c.status == 'held'])
        scheduled_calls = len([c for c in calls if c.status == 'scheduled'])
        missed_calls = len([c for c in calls if c.status in ['missed', 'no answer']])
        
        # Calculate total duration from content
        total_duration = 0
        for call in calls:
            if call.content:
                import re
                match = re.search(r'Duration: (\d+)', call.content)
                if match:
                    total_duration += int(match.group(1))
        
        return {
            'total_calls': total_calls,
            'held_calls': held_calls,
            'scheduled_calls': scheduled_calls,
            'missed_calls': missed_calls,
            'total_duration_minutes': total_duration,
            'average_duration_minutes': total_duration / held_calls if held_calls > 0 else 0
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/dashboard/enhanced")
async def get_enhanced_dashboard(
    current_user: User = Depends(get_current_user), 
    db: Session = Depends(get_db)
):
    """Get enhanced dashboard data with detailed analytics"""
    try:
        if PermissionChecker.is_admin(current_user):
            # Admin dashboard
            all_users = db.query(User).all()
            total_users = len(all_users)
            sales_managers = [u for u in all_users if u.role == UserRole.SALES_MANAGER]
            active_managers = len([m for m in sales_managers if m.is_active])
            
            all_leads = db.query(Lead).all()
            total_leads = len(all_leads)
            
            # Status breakdown
            status_counts = {
                'New': len([l for l in all_leads if l.status == 'New']),
                'Assigned': len([l for l in all_leads if l.status == 'Assigned']),
                'In Process': len([l for l in all_leads if l.status == 'In Process']),
                'Converted': len([l for l in all_leads if l.status == 'Converted'])
            }
            
            # Calculate total target
            total_target = sum(m.monthly_target or 0 for m in sales_managers)
            
            # Manager performance
            manager_performance = []
            for manager in sales_managers:
                manager_leads = [l for l in all_leads if l.assigned_to == manager.id]
                converted = len([l for l in manager_leads if l.status == 'Converted'])
                manager_performance.append({
                    'id': manager.id,
                    'name': manager.name,
                    'total_leads': len(manager_leads),
                    'converted': converted,
                    'conversion_rate': round((converted / len(manager_leads) * 100) if manager_leads else 0, 1)
                })
            
            # Sort by converted
            manager_performance.sort(key=lambda x: x['converted'], reverse=True)
            
            # Lead sources
            lead_sources = {}
            for lead in all_leads:
                source = lead.lead_source or 'Unknown'
                lead_sources[source] = lead_sources.get(source, 0) + 1
            
            return {
                'role': 'admin',
                'user_name': current_user.name,
                'stats': {
                    'total_users': total_users,
                    'total_leads': total_leads,
                    'active_managers': active_managers,
                    'total_managers': len(sales_managers),
                    'converted_leads': status_counts['Converted'],
                    'conversion_rate': round((status_counts['Converted'] / total_leads * 100) if total_leads > 0 else 0, 1),
                    'total_target': total_target
                },
                'status_counts': status_counts,
                'top_performers': manager_performance[:5],
                'lead_sources': lead_sources
            }
        else:
            # Sales Manager dashboard
            my_leads = db.query(Lead).filter(Lead.assigned_to == current_user.id).all()
            total_leads = len(my_leads)
            
            # Status breakdown
            status_counts = {
                'New': len([l for l in my_leads if l.status == 'New']),
                'Assigned': len([l for l in my_leads if l.status == 'Assigned']),
                'In Process': len([l for l in my_leads if l.status == 'In Process']),
                'Converted': len([l for l in my_leads if l.status == 'Converted'])
            }
            
            monthly_target = current_user.monthly_target or 0
            converted = status_counts['Converted']
            target_progress = round((converted / monthly_target * 100) if monthly_target > 0 else 0, 1)
            
            # Recent leads (last 5)
            recent_leads = sorted(my_leads, key=lambda x: x.id, reverse=True)[:5]
            recent_leads_data = [{
                'id': l.id,
                'first_name': l.first_name,
                'last_name': l.last_name,
                'email_address': l.email_address,
                'status': l.status
            } for l in recent_leads]
            
            # Lead sources
            lead_sources = {}
            for lead in my_leads:
                source = lead.lead_source or 'Unknown'
                lead_sources[source] = lead_sources.get(source, 0) + 1
            
            return {
                'role': 'sales_manager',
                'user_name': current_user.name,
                'stats': {
                    'total_leads': total_leads,
                    'converted_leads': converted,
                    'in_process_leads': status_counts['In Process'],
                    'conversion_rate': round((converted / total_leads * 100) if total_leads > 0 else 0, 1),
                    'monthly_target': monthly_target,
                    'target_progress': target_progress
                },
                'status_counts': status_counts,
                'recent_leads': recent_leads_data,
                'lead_sources': lead_sources
            }
            
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    
@app.post("/google/disconnect")
async def disconnect_google(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Disconnect Google Workspace for current user"""
    try:
        token = db.query(GoogleToken).filter(GoogleToken.user_id == current_user.id).first()
        if token:
            db.delete(token)
            db.commit()
            return {"message": "Google Workspace disconnected successfully"}
        return {"message": "No Google connection found"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    
import os
import shutil
from fastapi import UploadFile, File, Form
from fastapi.staticfiles import StaticFiles
from typing import List, Optional

# Configure file upload settings
UPLOAD_DIR = "uploads"
ATTACHMENT_DIR = os.path.join(UPLOAD_DIR, "attachments")
os.makedirs(ATTACHMENT_DIR, exist_ok=True)

# Mount static files for serving uploaded files
app.mount("/uploads", StaticFiles(directory=UPLOAD_DIR), name="uploads")

@app.post("/upload/file")
async def upload_file(
    file: UploadFile = File(...),
    lead_id: Optional[int] = Form(None),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Upload a file and optionally attach it to a lead"""
    try:
        # Validate file size (10MB limit)
        MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB
        file.file.seek(0, 2)  # Seek to end
        file_size = file.file.tell()
        file.file.seek(0)  # Reset to beginning
        
        if file_size > MAX_FILE_SIZE:
            raise HTTPException(status_code=400, detail="File size exceeds 10MB limit")
        
        # Generate safe filename
        original_filename = file.filename
        file_extension = os.path.splitext(original_filename)[1]
        safe_filename = f"{current_user.id}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}{file_extension}"
        file_path = os.path.join(ATTACHMENT_DIR, safe_filename)
        
        # Save file
        with open(file_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)
        
        # Create file attachment record
        attachment = FileAttachment(
            filename=safe_filename,
            original_filename=original_filename,
            file_path=file_path,
            file_size=file_size,
            mime_type=file.content_type or "application/octet-stream",
            lead_id=lead_id,
            user_id=current_user.id
        )
        
        db.add(attachment)
        db.commit()
        db.refresh(attachment)
        
        return {
            "id": attachment.id,
            "filename": original_filename,
            "file_url": f"/uploads/attachments/{safe_filename}",
            "file_size": file_size,
            "mime_type": file.content_type,
            "uploaded_at": attachment.created_at
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"File upload failed: {str(e)}")

@app.post("/upload/files")
async def upload_multiple_files(
    files: List[UploadFile] = File(...),
    lead_id: Optional[int] = Form(None),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Upload multiple files with improved error handling"""
    results = []
    
    for file in files:
        try:
            # Validate file size (10MB limit)
            MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB
            file.file.seek(0, 2)  # Seek to end
            file_size = file.file.tell()
            file.file.seek(0)  # Reset to beginning
            
            if file_size > MAX_FILE_SIZE:
                results.append({
                    "filename": file.filename, 
                    "error": "File size exceeds 10MB limit"
                })
                continue
            
            # Generate safe filename
            original_filename = file.filename
            file_extension = os.path.splitext(original_filename)[1]
            safe_filename = f"{current_user.id}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S%f')}{file_extension}"
            file_path = os.path.join(ATTACHMENT_DIR, safe_filename)
            
            # Save file
            with open(file_path, "wb") as buffer:
                shutil.copyfileobj(file.file, buffer)
            
            # Verify file was saved
            if not os.path.exists(file_path):
                results.append({
                    "filename": original_filename,
                    "error": "File failed to save"
                })
                continue
            
            print(f"File saved successfully: {file_path} ({file_size} bytes)")
            
            # Create file attachment record
            attachment = FileAttachment(
                filename=safe_filename,
                original_filename=original_filename,
                file_path=file_path,
                file_size=file_size,
                mime_type=file.content_type or "application/octet-stream",
                lead_id=lead_id,
                user_id=current_user.id
            )
            
            db.add(attachment)
            db.commit()
            db.refresh(attachment)
            
            results.append({
                "id": attachment.id,
                "filename": original_filename,
                "file_url": f"/uploads/attachments/{safe_filename}",
                "file_size": file_size,
                "mime_type": file.content_type,
                "uploaded_at": attachment.created_at.isoformat()
            })
            
        except Exception as e:
            print(f"Error uploading file {file.filename}: {str(e)}")
            import traceback
            traceback.print_exc()
            results.append({
                "filename": file.filename, 
                "error": str(e)
            })
    
    return {"uploads": results}


@app.get("/leads/{lead_id}/attachments")
async def get_lead_attachments(
    lead_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get all attachments for a lead"""
    attachments = db.query(FileAttachment).filter(
        FileAttachment.lead_id == lead_id
    ).order_by(FileAttachment.created_at.desc()).all()
    
    return [{
        'id': a.id,
        'filename': a.original_filename,
        'file_url': f"/uploads/attachments/{a.filename}",
        'file_size': a.file_size,
        'mime_type': a.mime_type,
        'uploaded_by': a.user.name,
        'uploaded_at': a.created_at
    } for a in attachments]

@app.delete("/attachments/{attachment_id}")
async def delete_attachment(
    attachment_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Delete a file attachment"""
    attachment = db.query(FileAttachment).filter(FileAttachment.id == attachment_id).first()
    if not attachment:
        raise HTTPException(status_code=404, detail="Attachment not found")
    
    # Check permissions
    if attachment.user_id != current_user.id and not PermissionChecker.is_admin(current_user):
        raise HTTPException(status_code=403, detail="Not authorized to delete this file")
    
    try:
        # Delete physical file
        if os.path.exists(attachment.file_path):
            os.remove(attachment.file_path)
        
        # Delete database record
        db.delete(attachment)
        db.commit()
        
        return {"message": "File deleted successfully"}
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Failed to delete file: {str(e)}")

# @app.put("/sales-managers/{user_id}/activate")
# async def activate_sales_manager(
#     user_id: int,
#     current_user: User = Depends(require_admin),
#     db: Session = Depends(get_db)
# ):
#     """Activate sales manager"""
#     try:
#         RoleManager.activate_user(db, user_id, current_user.id)
#         return {"message": "Sales manager activated successfully"}
#     except ValueError as e:
#         raise HTTPException(status_code=400, detail=str(e))

@app.put("/sales-managers/{user_id}/activate")
async def activate_sales_manager(
    user_id: int,
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db)
):
    """Activate sales manager"""
    try:
        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        
        user.is_active = True
        db.commit()
        db.refresh(user)
        
        # ✅ ADD: Timeline logging
        TimelineLogger.log_user_activated(db, current_user, user)
        
        return {"message": "Sales manager activated successfully"}
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=400, detail=str(e))
    
@app.put("/sales-managers/{user_id}/deactivate")
async def deactivate_sales_manager(
    user_id: int,
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db)
):
    """Deactivate sales manager"""
    try:
        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        
        user.is_active = False
        db.commit()
        db.refresh(user)
        
        # ✅ ADD: Timeline logging
        TimelineLogger.log_user_deactivated(db, current_user, user)
        
        return {"message": "Sales manager deactivated successfully"}
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=400, detail=str(e))

# @app.put("/sales-managers/{user_id}/deactivate")
# async def deactivate_sales_manager(
#     user_id: int,
#     current_user: User = Depends(require_admin),
#     db: Session = Depends(get_db)
# ):
#     """Deactivate sales manager"""
#     try:
#         RoleManager.deactivate_user(db, user_id, current_user.id)
#         return {"message": "Sales manager deactivated successfully"}
#     except ValueError as e:
#         raise HTTPException(status_code=400, detail=str(e))

# Updated endpoints for main.py - Fixed enum handling

@app.post("/leads", response_model=dict)
async def create_lead(
    lead_data: LeadCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Create a new lead with proper string handling"""
    try:
        # Create the lead object with string values instead of enums
        new_lead = Lead(
            salutation=lead_data.salutation,
            first_name=lead_data.first_name.strip(),
            last_name=lead_data.last_name.strip(),
            mobile_number=lead_data.mobile_number.strip(),
            alternate_mobile_number=lead_data.alternate_mobile_number.strip() if lead_data.alternate_mobile_number else None,
            email_address=lead_data.email_address.strip(),
            working_status=lead_data.working_status,
            street=lead_data.street.strip() if lead_data.street else None,
            postal_code=lead_data.postal_code.strip() if lead_data.postal_code else None,
            city=lead_data.city.strip() if lead_data.city else None,
            state=lead_data.state.strip() if lead_data.state else None,
            country=lead_data.country.strip() if lead_data.country else None,
            institute_name=lead_data.institute_name.strip() if lead_data.institute_name else None,
            qualification=lead_data.qualification.strip() if lead_data.qualification else None,
            course_interested_in=lead_data.course_interested_in.strip() if lead_data.course_interested_in else None,
            description=lead_data.description.strip() if lead_data.description else None,
            opportunity_amount=lead_data.opportunity_amount,
            lead_source=lead_data.lead_source,  # Store as string directly
            referred_by=lead_data.referred_by.strip() if lead_data.referred_by else None,
            status=lead_data.status or "New",  # Store as string directly
            status_description=lead_data.status_description.strip() if lead_data.status_description else None,
            assigned_to=lead_data.assigned_to,
        )
        
        # Add to database
        db.add(new_lead)
        db.commit()
        db.refresh(new_lead)

        # ADD THIS: Log timeline action
        TimelineLogger.log_lead_created(db, current_user, new_lead)      

        # Return the created lead as a dictionary
        return {
            "id": new_lead.id,
            "salutation": new_lead.salutation,
            "first_name": new_lead.first_name,
            "last_name": new_lead.last_name,
            "email_address": new_lead.email_address,
            "mobile_number": new_lead.mobile_number,
            "alternate_mobile_number": new_lead.alternate_mobile_number,
            "working_status": new_lead.working_status,
            "street": new_lead.street,
            "postal_code": new_lead.postal_code,
            "city": new_lead.city,
            "state": new_lead.state,
            "country": new_lead.country,
            "institute_name": new_lead.institute_name,
            "qualification": new_lead.qualification,
            "course_interested_in": new_lead.course_interested_in,
            "description": new_lead.description,
            "opportunity_amount": new_lead.opportunity_amount,
            "lead_source": new_lead.lead_source,  # Already a string
            "referred_by": new_lead.referred_by,
            "status": new_lead.status,  # Already a string
            "status_description": new_lead.status_description,
            "assigned_to": new_lead.assigned_to
        }
        
    except ValueError as e:
        raise HTTPException(status_code=400, detail=f"Validation error: {str(e)}")
    except Exception as e:
        db.rollback()
        print(f"Error creating lead: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to create lead: {str(e)}")

@app.get("/leads")
async def list_leads(
    skip: int = 0, 
    limit: int = 2000, 
    current_user: User = Depends(get_current_user), 
    db: Session = Depends(get_db)
):
    """Get leads with role-based access control"""
    try:
        if PermissionChecker.is_admin(current_user):
            leads = db.query(Lead).offset(skip).limit(limit).all()
        else:
            leads = db.query(Lead).filter(
                Lead.assigned_to == current_user.id
            ).offset(skip).limit(limit).all()
        
        # Convert to dictionaries with assigned user name
        leads_data = []
        for lead in leads:
            # Get assigned user's name
            assigned_to_name = None
            if lead.assigned_to:
                assigned_user = db.query(User).filter(User.id == lead.assigned_to).first()
                if assigned_user:
                    assigned_to_name = assigned_user.name
            
            lead_dict = {
                "id": lead.id,
                "salutation": lead.salutation,
                "first_name": lead.first_name,
                "last_name": lead.last_name,
                "email_address": lead.email_address,
                "mobile_number": lead.mobile_number,
                "alternate_mobile_number": lead.alternate_mobile_number,
                "working_status": lead.working_status,
                "street": lead.street,
                "postal_code": lead.postal_code,
                "city": lead.city,
                "state": lead.state,
                "country": lead.country,
                "institute_name": lead.institute_name,
                "qualification": lead.qualification,
                "course_interested_in": lead.course_interested_in,
                "description": lead.description,
                "opportunity_amount": lead.opportunity_amount,
                "lead_source": lead.lead_source,
                "referred_by": lead.referred_by,
                "status": lead.status or "New",
                "status_description": lead.status_description,
                "assigned_to": lead.assigned_to,
                "assigned_to_name": assigned_to_name  # Add this field
            }
            leads_data.append(lead_dict)
        
        return leads_data
        
    except Exception as e:
        print(f"Database error: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")
    
@app.put("/leads/{lead_id}")
async def update_lead(
    lead_id: int, 
    lead_data: LeadUpdate, 
    current_user: User = Depends(get_current_user), 
    db: Session = Depends(get_db)
):
    """Update lead details"""
    try:
        # Get the lead
        lead = db.query(Lead).filter(Lead.id == lead_id).first()
        if not lead:
            raise HTTPException(status_code=404, detail="Lead not found")
        
        # Track changes
        changed_fields = {}
        old_status = lead.status  # Store old status for status change logging
        old_assigned_to = lead.assigned_to  # Store old assignment

        # Check permissions
        if not PermissionChecker.is_admin(current_user):
            if lead.assigned_to != current_user.id:
                raise HTTPException(status_code=403, detail="Not authorized to update this lead")

        # Update fields that are provided
        update_data = lead_data.dict(exclude_unset=True)
        for key, value in update_data.items():
            if value is not None:
                # Handle string fields - strip whitespace
                if isinstance(value, str) and value.strip():
                    setattr(lead, key, value.strip())
                elif not isinstance(value, str):
                    setattr(lead, key, value)
                # For empty strings, set to None for optional fields
                elif key not in ['first_name', 'last_name', 'email_address', 'mobile_number']:
                    setattr(lead, key, None)

        db.commit()
        db.refresh(lead)

        # ADD THIS: Log timeline action only if something changed
        if changed_fields:
            TimelineLogger.log_lead_updated(db, current_user, lead, changed_fields)

        # Log status change separately if status was changed
        if 'status' in changed_fields:
            TimelineLogger.log_lead_status_change(
                db, 
                current_user, 
                lead, 
                changed_fields['status']['old'], 
                changed_fields['status']['new']
            )
        
        # Log assignment if assigned_to was changed
        if 'assigned_to' in changed_fields and lead.assigned_to:
            assigned_user = db.query(User).filter(User.id == lead.assigned_to).first()
            if assigned_user:
                TimelineLogger.log_lead_assigned(db, current_user, lead, assigned_user.name)
        
        # Return updated lead
        return {
            "id": lead.id,
            "salutation": lead.salutation,
            "first_name": lead.first_name,
            "last_name": lead.last_name,
            "email_address": lead.email_address,
            "mobile_number": lead.mobile_number,
            "alternate_mobile_number": lead.alternate_mobile_number,
            "working_status": lead.working_status,
            "street": lead.street,
            "postal_code": lead.postal_code,
            "city": lead.city,
            "state": lead.state,
            "country": lead.country,
            "institute_name": lead.institute_name,
            "qualification": lead.qualification,
            "course_interested_in": lead.course_interested_in,
            "description": lead.description,
            "opportunity_amount": lead.opportunity_amount,
            "lead_source": lead.lead_source,
            "referred_by": lead.referred_by,
            "status": lead.status or "New",
            "status_description": lead.status_description,
            "assigned_to": lead.assigned_to
        }
        
    except HTTPException:
        raise
    except ValueError as e:
        raise HTTPException(status_code=400, detail=f"Validation error: {str(e)}")
    except Exception as e:
        db.rollback()
        print(f"Error updating lead: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to update lead: {str(e)}")

@app.get("/leads/{lead_id}")
async def get_lead(
    lead_id: int, 
    current_user: User = Depends(get_current_user), 
    db: Session = Depends(get_db)
):
    """Get lead details with assigned user name"""
    try:
        lead = db.query(Lead).filter(Lead.id == lead_id).first()
        if not lead:
            raise HTTPException(status_code=404, detail="Lead not found")
        
        # Check permissions
        if not PermissionChecker.is_admin(current_user):
            if lead.assigned_to != current_user.id:
                raise HTTPException(status_code=403, detail="Not authorized to view this lead")
        
        # Get assigned user's name if assigned
        assigned_to_name = None
        if lead.assigned_to:
            assigned_user = db.query(User).filter(User.id == lead.assigned_to).first()
            if assigned_user:
                assigned_to_name = assigned_user.name
        
        return {
            "id": lead.id,
            "salutation": lead.salutation,
            "first_name": lead.first_name,
            "last_name": lead.last_name,
            "email_address": lead.email_address,
            "mobile_number": lead.mobile_number,
            "alternate_mobile_number": lead.alternate_mobile_number,
            "working_status": lead.working_status,
            "street": lead.street,
            "postal_code": lead.postal_code,
            "city": lead.city,
            "state": lead.state,
            "country": lead.country,
            "institute_name": lead.institute_name,
            "qualification": lead.qualification,
            "course_interested_in": lead.course_interested_in,
            "description": lead.description,
            "opportunity_amount": lead.opportunity_amount,
            "lead_source": lead.lead_source,
            "referred_by": lead.referred_by,
            "status": lead.status or "New",
            "status_description": lead.status_description,
            "assigned_to": lead.assigned_to,
            "assigned_to_name": assigned_to_name  # Add this field
        }
        
    except HTTPException:
        raise
    except Exception as e:
        print(f"Error fetching lead: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to fetch lead: {str(e)}")
    
from fastapi import UploadFile, File
import pandas as pd

@app.post("/leads/bulk", response_model=dict)
async def bulk_upload_leads(
    file: UploadFile = File(...),
    current_user: User = Depends(require_admin),  # Only admin can bulk import
    db: Session = Depends(get_db)
):
    """
    Bulk upload leads from a CSV file.
    Required CSV columns: first_name, last_name, email_address, mobile_number
    Optional columns: salutation, alternate_mobile_number, working_status, street, postal_code, city, state, country,
                      institute_name, qualification, course_interested_in, description, opportunity_amount,
                      lead_source, referred_by, status, status_description, assigned_to
    """
    if not file.filename.endswith(".csv"):
        raise HTTPException(status_code=400, detail="Only CSV files are supported")

    try:
        df = pd.read_csv(file.file)

        required_columns = ["first_name", "last_name", "email_address", "mobile_number"]
        missing_cols = [col for col in required_columns if col not in df.columns]
        if missing_cols:
            raise HTTPException(status_code=400, detail=f"Missing required columns: {missing_cols}")

        inserted = 0
        errors = []

        for idx, row in df.iterrows():
            try:
                lead = Lead(
                    salutation=row.get("salutation"),
                    first_name=str(row["first_name"]).strip(),
                    last_name=str(row["last_name"]).strip(),
                    mobile_number=str(row["mobile_number"]).strip(),
                    alternate_mobile_number=str(row.get("alternate_mobile_number")).strip() if row.get("alternate_mobile_number") else None,
                    email_address=str(row["email_address"]).strip(),
                    working_status=row.get("working_status"),
                    street=row.get("street"),
                    postal_code=row.get("postal_code"),
                    city=row.get("city"),
                    state=row.get("state"),
                    country=row.get("country"),
                    institute_name=row.get("institute_name"),
                    qualification=row.get("qualification"),
                    course_interested_in=row.get("course_interested_in"),
                    description=row.get("description"),
                    opportunity_amount=row.get("opportunity_amount"),
                    lead_source=row.get("lead_source"),
                    referred_by=row.get("referred_by"),
                    status=row.get("status") or "New",
                    status_description=row.get("status_description"),
                    assigned_to=int(row.get("assigned_to")) if row.get("assigned_to") else None
                )
                db.add(lead)
                inserted += 1
            except Exception as e:
                errors.append({"row": idx + 2, "error": str(e)})  # +2 for CSV header + 0-index

        db.commit()
        return {
            "message": f"Bulk upload completed: {inserted} leads inserted",
            "errors": errors
        }

    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Failed to process CSV: {str(e)}")
        
    
# ============== GOOGLE WORKSPACE INTEGRATION ==============
# global dict to store state temporarily
oauth_state_store = {}

from fastapi import Depends, HTTPException
from urllib.parse import urlencode
import uuid
import os

@app.get("/google/auth")
async def google_auth(current_user: User = Depends(get_current_user)):
    """
    Generate Google OAuth URL for the user.
    """
    try:
        # Generate a random state ID and store user_id
        state_id = str(uuid.uuid4())
        oauth_state_store[state_id] = current_user.id

        # OAuth parameters
        params = {
            "client_id": os.getenv("GOOGLE_CLIENT_ID"),
            "response_type": "code",
            "scope": "https://www.googleapis.com/auth/calendar https://www.googleapis.com/auth/gmail.send https://www.googleapis.com/auth/gmail.readonly",
            "redirect_uri": os.getenv("GOOGLE_REDIRECT_URI"),  # e.g., http://localhost:8000/auth/google/callback
            "access_type": "offline",
            "prompt": "consent",
            "state": state_id
        }

        auth_url = f"https://accounts.google.com/o/oauth2/v2/auth?{urlencode(params)}"
        return {"authorization_url": auth_url}

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

from fastapi import Query, Depends
from sqlalchemy.orm import Session
import json
from fastapi.responses import RedirectResponse
from google_integration import GoogleWorkspaceManager  # your existing manager

@app.get("/auth/google/callback")
async def google_callback(
    code: str = Query(...),
    state: str = Query(...),
    db: Session = Depends(get_db)
):
    """
    Handle Google OAuth callback.
    """
    try:
        # Verify state
        user_id = oauth_state_store.get(state)
        if not user_id:
            raise HTTPException(status_code=400, detail="Invalid OAuth state")

        # Exchange authorization code for tokens
        token_data = GoogleWorkspaceManager.exchange_code_for_token(code)

        # Store/update token in DB
        existing_token = db.query(GoogleToken).filter(GoogleToken.user_id == user_id).first()
        if existing_token:
            existing_token.token = token_data['token']
            existing_token.refresh_token = token_data.get('refresh_token')
            existing_token.token_uri = token_data['token_uri']
            existing_token.client_id = token_data['client_id']
            existing_token.client_secret = token_data['client_secret']
            existing_token.scopes = json.dumps(token_data['scopes'])
        else:
            new_token = GoogleToken(
                user_id=user_id,
                token=token_data['token'],
                refresh_token=token_data.get('refresh_token'),
                token_uri=token_data['token_uri'],
                client_id=token_data['client_id'],
                client_secret=token_data['client_secret'],
                scopes=json.dumps(token_data['scopes'])
            )
            db.add(new_token)

        db.commit()

        # Remove used state
        oauth_state_store.pop(state, None)

        # Redirect to frontend leads page
        return RedirectResponse(url="http://127.0.0.1:5500/leads.html")

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/google/status")
async def google_status(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Check if user has connected Google Workspace"""
    token = db.query(GoogleToken).filter(GoogleToken.user_id == current_user.id).first()
    return {"connected": token is not None}

@app.post("/google/calendar/event")
async def create_calendar_event(
    event_data: dict,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Create a Google Calendar event with Google Meet link - sends professional Google Calendar invite"""
    try:
        # Get user's Google token
        token = db.query(GoogleToken).filter(GoogleToken.user_id == current_user.id).first()
        if not token:
            raise HTTPException(status_code=400, detail="Google Workspace not connected")
        
        # Get lead details for attendee email
        lead = db.query(Lead).filter(Lead.id == event_data.get('lead_id')).first()
        if not lead:
            raise HTTPException(status_code=404, detail="Lead not found")
        
        # Prepare credentials
        creds_data = {
            'token': token.token,
            'refresh_token': token.refresh_token,
            'token_uri': token.token_uri,
            'client_id': token.client_id,
            'client_secret': token.client_secret,
            'scopes': json.loads(token.scopes)
        }
        credentials = GoogleWorkspaceManager.get_credentials(creds_data)
        
        # ✅ CHANGED: Support multiple attendees from frontend
        # If frontend sends attendee_emails, use it; otherwise default to lead email only
        if event_data.get('attendee_emails'):
            # Frontend already combined lead + participants
            event_data['attendee_emails'] = event_data['attendee_emails']
        else:
            # Fallback: just the lead email
            event_data['attendee_emails'] = [lead.email_address]
        
        # Create calendar event (Google Calendar will send professional invite to ALL attendees)
        calendar_result = CalendarManager.create_event(credentials, event_data)
        
        # ✅ CHANGED: Store participants info in communication
        participants_list = event_data.get('participants', '')  # comma-separated participant emails
        communication_content = event_data.get('description', '')
        
        # Add participants info to content if provided
        if participants_list:
            all_attendees = event_data['attendee_emails']
            communication_content += f"\n\nParticipants: {', '.join(all_attendees)}"
        
        # Log communication in CRM
        communication = Communication(
            lead_id=event_data.get('lead_id'),
            user_id=current_user.id,
            type='meeting',
            subject=event_data['title'],
            content=communication_content,  # ✅ CHANGED: Now includes participants
            scheduled_at=datetime.fromisoformat(event_data['start_time'].replace('Z', '+00:00')),
            status='scheduled',
            google_event_id=calendar_result['event_id'],
            meet_link=calendar_result['meet_link']
        )
        db.add(communication)
        db.commit()
        
        # ✅ CHANGED: Updated success message
        attendee_count = len(event_data['attendee_emails'])
        return {
            **calendar_result,
            'message': f'Calendar event created and invitations sent to {attendee_count} attendee(s)'
        }
        
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=str(e))
    
# Add these endpoints to main.py after the complete meeting endpoint

from pydantic import BaseModel
from typing import Optional

class MeetingReschedule(BaseModel):
    title: str
    description: Optional[str] = None
    start_time: str
    end_time: str
    attendee_emails: Optional[list] = None

@app.get("/communications/{communication_id}")
async def get_communication(
    communication_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get single communication/meeting details"""
    communication = db.query(Communication).filter(
        Communication.id == communication_id
    ).first()
    
    if not communication:
        raise HTTPException(status_code=404, detail="Communication not found")
    
    return {
        'id': communication.id,
        'lead_id': communication.lead_id,
        'type': communication.type,
        'subject': communication.subject,
        'content': communication.content,
        'scheduled_at': communication.scheduled_at,
        'completed_at': communication.completed_at,
        'status': communication.status,
        'meet_link': communication.meet_link,
        'google_event_id': communication.google_event_id,
        'created_at': communication.created_at
    }


# Replace the existing /communications/{id}/reschedule endpoint in main.py with this:

from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import base64
from googleapiclient.discovery import build
from google.oauth2.credentials import Credentials
import json

# Add this import at the top of main.py
from datetime import datetime, timedelta
import pytz

# Add this helper function near the top of main.py (after imports)
def convert_to_ist(utc_time):
    """Convert UTC datetime to IST"""
    if utc_time is None:
        return None
    
    # If datetime is naive (no timezone), assume it's UTC
    if utc_time.tzinfo is None:
        utc_time = pytz.utc.localize(utc_time)
    
    ist = pytz.timezone('Asia/Kolkata')
    return utc_time.astimezone(ist)

def format_ist_datetime(dt):
    """Format datetime in IST for display"""
    if dt is None:
        return "Not scheduled"
    
    ist_time = convert_to_ist(dt)
    return ist_time.strftime('%B %d, %Y at %I:%M %p IST')


# Replace the /communications/{id}/reschedule endpoint with this updated version:

@app.put("/communications/{communication_id}/reschedule")
async def reschedule_meeting(
    communication_id: int,
    meeting_data: MeetingReschedule,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Reschedule a meeting - updates calendar and notifies all attendees"""
    try:
        # Get the communication record
        communication = db.query(Communication).filter(
            Communication.id == communication_id,
            Communication.type == 'meeting'
        ).first()
        
        if not communication:
            raise HTTPException(status_code=404, detail="Meeting not found")
        
        # Get lead details
        lead = db.query(Lead).filter(Lead.id == communication.lead_id).first()
        if not lead:
            raise HTTPException(status_code=404, detail="Lead not found")
        
        # Store old meeting details for notification
        old_date = communication.scheduled_at
        
        # Parse new datetime - handle both UTC and IST input
        new_start_time = datetime.fromisoformat(meeting_data.start_time.replace('Z', '+00:00'))
        new_end_time = datetime.fromisoformat(meeting_data.end_time.replace('Z', '+00:00'))
        
        # Update meeting details in database (store in UTC)
        communication.subject = meeting_data.title
        communication.content = meeting_data.description
        communication.scheduled_at = new_start_time
        communication.status = 'rescheduled'
        
        # Try to update Google Calendar event if integrated
        google_calendar_updated = False
        try:
            token = db.query(GoogleToken).filter(GoogleToken.user_id == current_user.id).first()
            if token and communication.google_event_id:
                # Update Google Calendar event
                creds_data = {
                    'token': token.token,
                    'refresh_token': token.refresh_token,
                    'token_uri': token.token_uri,
                    'client_id': token.client_id,
                    'client_secret': token.client_secret,
                    'scopes': json.loads(token.scopes)
                }
                credentials = GoogleWorkspaceManager.get_credentials(creds_data)
                
                # Update the calendar event with IST timezone
                service = build('calendar', 'v3', credentials=credentials)
                event = service.events().get(
                    calendarId='primary',
                    eventId=communication.google_event_id
                ).execute()
                
                # Update event details with IST timezone
                event['summary'] = meeting_data.title
                event['description'] = meeting_data.description
                event['start'] = {
                    'dateTime': meeting_data.start_time,
                    'timeZone': 'Asia/Kolkata'  # ✅ Fixed: Use IST timezone
                }
                event['end'] = {
                    'dateTime': meeting_data.end_time,
                    'timeZone': 'Asia/Kolkata'  # ✅ Fixed: Use IST timezone
                }
                
                # Update with notification to all attendees
                updated_event = service.events().update(
                    calendarId='primary',
                    eventId=communication.google_event_id,
                    body=event,
                    sendUpdates='all'
                ).execute()
                
                google_calendar_updated = True
                
        except Exception as e:
            print(f"Google Calendar update failed: {str(e)}")
        
        # If Google Calendar not integrated, send manual email notification
        if not google_calendar_updated:
            try:
                # Extract all attendees
                attendees = [lead.email_address]
                if communication.content:
                    import re
                    participants_match = re.search(r'Participants: (.+?)(?:\n|$)', communication.content)
                    if participants_match:
                        participants = [p.strip() for p in participants_match.group(1).split(',')]
                        attendees.extend(participants)
                
                # Format dates in IST for email
                old_date_ist = format_ist_datetime(old_date)
                new_date_ist = format_ist_datetime(new_start_time)
                
                notification_subject = f"Meeting Rescheduled: {meeting_data.title}"
                notification_body = f"""
                <html>
                <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
                    <div style="max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #ddd; border-radius: 10px;">
                        <h2 style="color: #f59e0b; border-bottom: 2px solid #f59e0b; padding-bottom: 10px;">
                            Meeting Rescheduled
                        </h2>
                        
                        <p>Hello,</p>
                        
                        <p>Your meeting has been rescheduled to a new date and time.</p>
                        
                        <div style="background: #f9fafb; padding: 15px; border-radius: 8px; margin: 20px 0;">
                            <h3 style="margin-top: 0; color: #1f2937;">Meeting Details:</h3>
                            <p><strong>Title:</strong> {meeting_data.title}</p>
                            <p><strong>Previous Date:</strong> {old_date_ist}</p>
                            <p><strong>New Date:</strong> {new_date_ist}</p>
                            {f'<p><strong>Description:</strong> {meeting_data.description}</p>' if meeting_data.description else ''}
                            {f'<p><strong>Meet Link:</strong> <a href="{communication.meet_link}">{communication.meet_link}</a></p>' if communication.meet_link else ''}
                        </div>
                        
                        <p>If you have any questions, please contact {current_user.name}.</p>
                        
                        <p style="color: #6b7280; font-size: 12px; margin-top: 30px; padding-top: 20px; border-top: 1px solid #e5e7eb;">
                            This is an automated notification. All times are in Indian Standard Time (IST).
                        </p>
                    </div>
                </body>
                </html>
                """
                
                # Send via Gmail if integrated
                token = db.query(GoogleToken).filter(GoogleToken.user_id == current_user.id).first()
                if token:
                    try:
                        creds_data = {
                            'token': token.token,
                            'refresh_token': token.refresh_token,
                            'token_uri': token.token_uri,
                            'client_id': token.client_id,
                            'client_secret': token.client_secret,
                            'scopes': json.loads(token.scopes)
                        }
                        credentials = GoogleWorkspaceManager.get_credentials(creds_data)
                        
                        for attendee_email in attendees:
                            GmailManager.send_email(credentials, {
                                'to': attendee_email,
                                'subject': notification_subject,
                                'body': notification_body,
                                'is_html': True
                            })
                    except Exception as email_error:
                        print(f"Failed to send email: {str(email_error)}")
                        
            except Exception as notify_error:
                print(f"Notification failed: {str(notify_error)}")
        
        db.commit()
        db.refresh(communication)

        # ✅ ADD: Timeline logging
        lead = db.query(Lead).filter(Lead.id == communication.lead_id).first()
        lead_name = f"{lead.first_name} {lead.last_name}" if lead else "Unknown"
        changes = {
            "status": {
                "old": communication.status,
                "new": "rescheduled"
            },
            "scheduled_at": {
                "old": str(old_date),
                "new": str(new_start_time)
            }
        }
        TimelineLogger.log_communication_updated(db, current_user, communication, lead_name, changes)
        
        return {
            'id': communication.id,
            'status': communication.status,
            'scheduled_at': communication.scheduled_at,
            'google_calendar_updated': google_calendar_updated,
            'message': 'Meeting rescheduled and attendees notified' if google_calendar_updated else 'Meeting rescheduled'
        }
        
    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Failed to reschedule meeting: {str(e)}")


# Also update the create calendar event endpoint - find this in main.py and update the timezone:
# In the /google/calendar/event endpoint, change:
# 'timeZone': event_data.get('timezone', 'UTC')
# TO:
# 'timeZone': 'Asia/Kolkata'

@app.put("/communications/{communication_id}/cancel")
async def cancel_meeting(
    communication_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Cancel a meeting - automatically sets status to 'cancelled'"""
    try:
        # Get the communication record
        communication = db.query(Communication).filter(
            Communication.id == communication_id,
            Communication.type == 'meeting'
        ).first()
        
        if not communication:
            raise HTTPException(status_code=404, detail="Meeting not found")
        
        # Automatically set status to 'cancelled'
        communication.status = 'cancelled'
        
        db.commit()
        db.refresh(communication)

        # ✅ ADD: Timeline logging
        lead = db.query(Lead).filter(Lead.id == communication.lead_id).first()
        lead_name = f"{lead.first_name} {lead.last_name}" if lead else "Unknown"
        changes = {
            "status": {
                "old": communication.status,
                "new": "cancelled"
            }
        }
        TimelineLogger.log_communication_updated(db, current_user, communication, lead_name, changes)

        
        
        # TODO: If Google Calendar integration, cancel the calendar event here
        # if communication.google_event_id:
        #     cancel_google_calendar_event(communication.google_event_id)
        
        return {
            'id': communication.id,
            'status': communication.status,
            'message': 'Meeting cancelled successfully'
        }
        
    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Failed to cancel meeting: {str(e)}")
    
from pydantic import BaseModel
from typing import Optional

# Simple model for meeting completion with feedback
class MeetingComplete(BaseModel):
    feedback: Optional[str] = None

# Modified mark_meeting_complete endpoint to restrict to admin only
@app.put("/communications/{communication_id}/complete")
async def mark_meeting_complete(
    communication_id: int,
    meeting_data: Optional[MeetingComplete] = None,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Mark a meeting as completed with optional feedback (Admin only)"""
    try:
        # Get the communication record
        communication = db.query(Communication).filter(
            Communication.id == communication_id,
            Communication.type == 'meeting'
        ).first()
        
        if not communication:
            raise HTTPException(status_code=404, detail="Meeting not found")
        
        # Check if user is admin
        is_admin = PermissionChecker.is_admin(current_user)
        is_creator = communication.user_id == current_user.id
        
        # Only allow marking as complete if user is admin
        if not is_admin:
            raise HTTPException(
                status_code=403, 
                detail="Only admins can mark meetings as complete and provide feedback"
            )
        
        # Update to completed
        communication.status = 'completed'
        communication.completed_at = datetime.utcnow()
        
        # Add feedback if provided
        if meeting_data and meeting_data.feedback:
            communication.feedback = meeting_data.feedback
        
        db.commit()
        db.refresh(communication)

        # Timeline logging
        lead = db.query(Lead).filter(Lead.id == communication.lead_id).first()
        lead_name = f"{lead.first_name} {lead.last_name}" if lead else "Unknown"
        changes = {
            "status": {
                "old": communication.status,
                "new": "completed"
            }
        }
        TimelineLogger.log_communication_updated(db, current_user, communication, lead_name, changes)

        
        return {
            'id': communication.id,
            'status': communication.status,
            'feedback': communication.feedback,
            'message': 'Meeting completed successfully'
        }
        
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Failed to complete meeting: {str(e)}")    

@app.get("/google/calendar/events")
async def get_calendar_events(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get upcoming calendar events"""
    try:
        token = db.query(GoogleToken).filter(GoogleToken.user_id == current_user.id).first()
        if not token:
            raise HTTPException(status_code=400, detail="Google Workspace not connected")
        
        creds_data = {
            'token': token.token,
            'refresh_token': token.refresh_token,
            'token_uri': token.token_uri,
            'client_id': token.client_id,
            'client_secret': token.client_secret,
            'scopes': json.loads(token.scopes)
        }
        credentials = GoogleWorkspaceManager.get_credentials(creds_data)
        
        events = CalendarManager.get_upcoming_events(credentials)
        return {"events": events}
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# @app.post("/google/gmail/send")
# async def send_email(
#     email_data: dict,
#     current_user: User = Depends(get_current_user),
#     db: Session = Depends(get_db)
# ):
#     """Send email via Gmail"""
#     try:
#         token = db.query(GoogleToken).filter(GoogleToken.user_id == current_user.id).first()
#         if not token:
#             raise HTTPException(status_code=400, detail="Google Workspace not connected")
        
#         creds_data = {
#             'token': token.token,
#             'refresh_token': token.refresh_token,
#             'token_uri': token.token_uri,
#             'client_id': token.client_id,
#             'client_secret': token.client_secret,
#             'scopes': json.loads(token.scopes)
#         }
#         credentials = GoogleWorkspaceManager.get_credentials(creds_data)
        
#         result = GmailManager.send_email(credentials, email_data)
        
#         # Log communication
#         communication = Communication(
#             lead_id=email_data.get('lead_id'),
#             user_id=current_user.id,
#             type='email',
#             subject=email_data['subject'],
#             content=email_data['body'],
#             completed_at=datetime.utcnow(),
#             status='completed',
#             google_message_id=result['message_id']
#         )
#         db.add(communication)
#         db.commit()
        
#         return result
        
#     except Exception as e:
#         raise HTTPException(status_code=500, detail=str(e))

@app.post("/google/gmail/send-with-attachments")
async def send_email_with_attachments(
    email_data: dict,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Send email with file attachments via Gmail"""
    try:
        # Get Google token
        token = db.query(GoogleToken).filter(GoogleToken.user_id == current_user.id).first()
        if not token:
            raise HTTPException(status_code=400, detail="Google Workspace not connected. Please connect your Google account first.")
        
        # Prepare credentials
        creds_data = {
            'token': token.token,
            'refresh_token': token.refresh_token,
            'token_uri': token.token_uri,
            'client_id': token.client_id,
            'client_secret': token.client_secret,
            'scopes': json.loads(token.scopes)
        }
        credentials = GoogleWorkspaceManager.get_credentials(creds_data)
        
        # Process attachments if provided
        attachments = []
        attachment_ids = email_data.get('attachment_ids', [])
        
        print(f"Processing {len(attachment_ids)} attachments")
        
        for attachment_id in attachment_ids:
            attachment = db.query(FileAttachment).filter(FileAttachment.id == attachment_id).first()
            
            if attachment and os.path.exists(attachment.file_path):
                print(f"Reading attachment: {attachment.original_filename}")
                try:
                    with open(attachment.file_path, 'rb') as f:
                        file_data = f.read()
                        attachments.append({
                            'filename': attachment.original_filename,
                            'file_data': file_data
                        })
                        print(f"Successfully read {len(file_data)} bytes from {attachment.original_filename}")
                except Exception as e:
                    print(f"Error reading file {attachment.file_path}: {str(e)}")
                    # Continue with other attachments instead of failing completely
                    continue
            else:
                print(f"Attachment {attachment_id} not found or file doesn't exist")
        
        print(f"Prepared {len(attachments)} attachments for email")
        
        # Send email with attachments
        result = GmailManager.send_email_with_attachments(credentials, email_data, attachments)
        
        # Log communication in CRM
        communication = Communication(
            lead_id=email_data.get('lead_id'),
            user_id=current_user.id,
            type='email',
            subject=email_data['subject'],
            content=email_data['body'],
            completed_at=convert_to_ist(datetime.utcnow()),
            status='completed',
            google_message_id=result['message_id']
        )
        db.add(communication)
        db.commit()
        db.refresh(communication)
        
        # Link attachments to communication
        for attachment_id in attachment_ids:
            attachment = db.query(FileAttachment).filter(FileAttachment.id == attachment_id).first()
            if attachment:
                attachment.communication_id = communication.id
        
        db.commit()
        
        return {
            **result,
            'message': 'Email sent successfully',
            'attachment_count': len(attachments),
            'communication_id': communication.id
        }
        
    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        print(f"Email sending error: {str(e)}")
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Failed to send email: {str(e)}")


@app.get("/leads/{lead_id}/communications")
async def get_lead_communications(
    lead_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get all communications for a lead"""
    # Verify lead exists
    lead = db.query(Lead).filter(Lead.id == lead_id).first()
    if not lead:
        raise HTTPException(status_code=404, detail="Lead not found")

    # Check if user has access to this lead
    if current_user.role != UserRole.ADMIN and lead.assigned_to != current_user.id:
        raise HTTPException(status_code=403, detail="Not authorized to access this lead")

    # Get communications
    communications = db.query(Communication).filter(
        Communication.lead_id == lead_id
    ).order_by(Communication.created_at.desc()).all()

    result = []
    for comm in communications:
        # Include the feedback field in the response
        result.append({
            "id": comm.id,
            "type": comm.type,
            "subject": comm.subject,
            "content": comm.content,
            "scheduled_at": comm.scheduled_at,
            "completed_at": comm.completed_at,
            "status": comm.status,
            "meet_link": comm.meet_link,
            "google_event_id": comm.google_event_id,
            "google_message_id": comm.google_message_id,
            "feedback": comm.feedback,  # Add this line to include the feedback field
            "created_at": comm.created_at,
            "user_id": comm.user_id
        })

    return result

@app.delete("/leads/{lead_id}")
async def delete_lead(
    lead_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Delete a lead - ADMIN ONLY"""
    try:
        # Check if user is admin
        if not PermissionChecker.is_admin(current_user):
            raise HTTPException(
                status_code=403, 
                detail="Admin permission required to delete leads"
            )
        
        # Get the lead
        lead = db.query(Lead).filter(Lead.id == lead_id).first()
        
        if not lead:
            raise HTTPException(status_code=404, detail="Lead not found")
        
        lead_name = f"{lead.first_name} {lead.last_name}"
        
        # Hard delete - permanently remove from database
        db.delete(lead)
        db.commit()

        # Log timeline action
        TimelineLogger.log_lead_deleted(db, current_user, lead_id, lead_name)

        return {
            "message": "Lead deleted successfully",
            "lead_id": lead_id
        }
        
    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        print(f"Error deleting lead: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to delete lead: {str(e)}")

from datetime import datetime, timedelta
from sqlalchemy import func, and_
from typing import Optional

@app.get("/reports/sales-performance")
async def get_sales_performance_report(
    period: str = "weekly",  # daily, weekly, monthly
    user_id: Optional[int] = None,
    date: Optional[str] = None,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Get sales performance reports with detailed call and demo statistics
    """
    try:
        # Determine date range based on period
        if date:
            target_date = datetime.strptime(date, "%Y-%m-%d")
        else:
            target_date = datetime.utcnow()
        
        if period == "daily":
            start_date = target_date.replace(hour=0, minute=0, second=0, microsecond=0)
            end_date = start_date + timedelta(days=1)
            prev_start_date = start_date - timedelta(days=1)
            prev_end_date = start_date
        elif period == "weekly":
            # Start from Monday of the week
            days_since_monday = target_date.weekday()
            start_date = target_date - timedelta(days=days_since_monday)
            start_date = start_date.replace(hour=0, minute=0, second=0, microsecond=0)
            end_date = start_date + timedelta(days=7)
            prev_start_date = start_date - timedelta(days=7)
            prev_end_date = start_date
        else:  # monthly
            start_date = target_date.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
            # Get last day of month
            if target_date.month == 12:
                end_date = start_date.replace(year=target_date.year + 1, month=1)
            else:
                end_date = start_date.replace(month=target_date.month + 1)
            # Previous month
            if start_date.month == 1:
                prev_start_date = start_date.replace(year=start_date.year - 1, month=12)
            else:
                prev_start_date = start_date.replace(month=start_date.month - 1)
            prev_end_date = start_date
        
        # Get users to analyze (either specific user or based on role)
        if user_id:
            # Specific user requested
            if not PermissionChecker.is_admin(current_user) and current_user.id != user_id:
                raise HTTPException(status_code=403, detail="Access denied")
            users_query = db.query(User).filter(User.id == user_id)
        elif PermissionChecker.is_admin(current_user):
            # Admin sees all sales managers
            users_query = db.query(User).filter(User.role == UserRole.SALES_MANAGER)
        else:
            # Sales manager sees only themselves
            users_query = db.query(User).filter(User.id == current_user.id)
        
        users = users_query.all()
        
        # Initialize summary metrics
        total_calls_dialed = 0
        total_calls_answered = 0
        total_demos_scheduled = 0
        total_demos_completed = 0
        total_revenue = 0
        total_activities = 0
        
        # Previous period metrics
        prev_calls_dialed = 0
        prev_calls_answered = 0
        prev_demos_scheduled = 0
        prev_demos_completed = 0
        prev_revenue = 0
        prev_activities = 0
        
        team_performance = []
        
        for user in users:
            # ===== CURRENT PERIOD =====
            
            # Get all calls
            all_calls = db.query(Communication).filter(
                and_(
                    Communication.user_id == user.id,
                    Communication.type == 'call',
                    Communication.created_at >= start_date,
                    Communication.created_at < end_date
                )
            ).all()
            
            calls_dialed = len(all_calls)
            
            # Count calls that were answered (status: 'completed', 'held', or similar success indicators)
            # Adjust these status values based on your actual data
            calls_answered = len([c for c in all_calls if c.status and c.status.lower() in ['completed', 'held', 'answered', 'successful']])
            
            # Get all demos/meetings
            all_demos = db.query(Communication).filter(
                and_(
                    Communication.user_id == user.id,
                    Communication.type == 'meeting',
                    Communication.created_at >= start_date,
                    Communication.created_at < end_date
                )
            ).all()
            
            demos_scheduled = len(all_demos)
            
            # Count demos that were completed
            demos_completed = len([d for d in all_demos if d.status and d.status.lower() in ['completed', 'done', 'held']])
            
            # Revenue from converted leads
            converted_leads = db.query(Lead).filter(
                and_(
                    Lead.assigned_to == user.id,
                    Lead.status == 'Converted'
                )
            ).all()
            revenue_generated = sum(lead.opportunity_amount or 0 for lead in converted_leads)
            
            # Total activities
            all_activities = db.query(Communication).filter(
                and_(
                    Communication.user_id == user.id,
                    Communication.created_at >= start_date,
                    Communication.created_at < end_date
                )
            ).count()

            # Calculate talk time from calls
            total_talk_time = 0
            for call in all_calls:
                if call.status and call.status.lower() in ['completed', 'held']:
                    # Extract duration using regex
                    import re
                    if call.content:
                        match = re.search(r'Duration: (\d+)', call.content)
                        if match:
                            total_talk_time += int(match.group(1))

             # Previous period talk time
            prev_talk_time = 0
            for call in prev_all_calls:
                if call.status and call.status.lower() in ['completed', 'held']:
                    if call.content:
                        match = re.search(r'Duration: (\d+)', call.content)
                        if match:
                            prev_talk_time += int(match.group(1))
            
            # ===== PREVIOUS PERIOD =====
            
            prev_all_calls = db.query(Communication).filter(
                and_(
                    Communication.user_id == user.id,
                    Communication.type == 'call',
                    Communication.created_at >= prev_start_date,
                    Communication.created_at < prev_end_date
                )
            ).all()
            
            prev_calls_dialed_user = len(prev_all_calls)
            prev_calls_answered_user = len([c for c in prev_all_calls if c.status and c.status.lower() in ['completed', 'held', 'answered', 'successful']])
            
            prev_all_demos = db.query(Communication).filter(
                and_(
                    Communication.user_id == user.id,
                    Communication.type == 'meeting',
                    Communication.created_at >= prev_start_date,
                    Communication.created_at < prev_end_date
                )
            ).all()
            
            prev_demos_scheduled_user = len(prev_all_demos)
            prev_demos_completed_user = len([d for d in prev_all_demos if d.status and d.status.lower() in ['completed', 'done', 'held']])
            
            prev_converted_leads = db.query(Lead).filter(
                and_(
                    Lead.assigned_to == user.id,
                    Lead.status == 'Converted'
                )
            ).all()
            prev_revenue_user = sum(lead.opportunity_amount or 0 for lead in prev_converted_leads)
            
            prev_activities_user = db.query(Communication).filter(
                and_(
                    Communication.user_id == user.id,
                    Communication.created_at >= prev_start_date,
                    Communication.created_at < prev_end_date
                )
            ).count()
            
            # Add to totals
            total_calls_dialed += calls_dialed
            total_calls_answered += calls_answered
            total_demos_scheduled += demos_scheduled
            total_demos_completed += demos_completed
            total_revenue += revenue_generated
            total_activities += all_activities
            
            prev_calls_dialed += prev_calls_dialed_user
            prev_calls_answered += prev_calls_answered_user
            prev_demos_scheduled += prev_demos_scheduled_user
            prev_demos_completed += prev_demos_completed_user
            prev_revenue += prev_revenue_user
            prev_activities += prev_activities_user
            
            # Add to team performance
            team_performance.append({
                'name': user.name,
                'user_id': user.id,
                'calls_dialed': calls_dialed,
                'calls_answered': calls_answered,
                'demos_scheduled': demos_scheduled,
                'demos_completed': demos_completed,
                'revenue_generated': round(revenue_generated, 2),
                'activities': all_activities,
                'talk_time': total_talk_time  
            })

            # Track totals
            total_talk_time_all = sum(member['talk_time'] for member in team_performance)
            prev_talk_time_all = sum(prev_talk_time)  # Simplified - you may need to adjust based on your data structure
        
        talk_time_change = calculate_change(total_talk_time_all, prev_talk_time_all)

        # Sort team performance by revenue (descending)
        team_performance.sort(key=lambda x: x['revenue_generated'], reverse=True)
        
        # Calculate percentage changes
        def calculate_change(current, previous):
            if previous == 0:
                return 100 if current > 0 else 0
            return round(((current - previous) / previous) * 100, 1)
        
        calls_dialed_change = calculate_change(total_calls_dialed, prev_calls_dialed)
        calls_answered_change = calculate_change(total_calls_answered, prev_calls_answered)
        demos_scheduled_change = calculate_change(total_demos_scheduled, prev_demos_scheduled)
        demos_completed_change = calculate_change(total_demos_completed, prev_demos_completed)
        revenue_change = calculate_change(total_revenue, prev_revenue)
        activities_change = calculate_change(total_activities, prev_activities)
        
        return {
            'period': period,
            'date_range': {
                'start': start_date.isoformat(),
                'end': end_date.isoformat()
            },
            'summary': {
                'total_calls_dialed': total_calls_dialed,
                'total_calls_answered': total_calls_answered,
                'total_demos_scheduled': total_demos_scheduled,
                'total_demos_completed': total_demos_completed,
                'total_revenue': round(total_revenue, 2),
                'total_activities': total_activities,
                'calls_dialed_change': calls_dialed_change,
                'calls_answered_change': calls_answered_change,
                'demos_scheduled_change': demos_scheduled_change,
                'demos_completed_change': demos_completed_change,
                'revenue_change': revenue_change,
                'activities_change': activities_change,
                'total_talk_time': total_talk_time_all,
                'talk_time_change': talk_time_change
            },
            'team_performance': team_performance
        }
        
    except HTTPException:
        raise
    except Exception as e:
        print(f"Error generating sales performance report: {str(e)}")
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Failed to generate report: {str(e)}")


# Keep the /users endpoint as is
@app.get("/users")
async def get_all_users(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Get list of users for dropdown filters
    - Admins see all sales managers
    - Sales managers see only themselves
    """
    try:
        if PermissionChecker.is_admin(current_user):
            # Admin sees all sales managers
            users = db.query(User).filter(User.role == UserRole.SALES_MANAGER).all()
            return [{
                "id": u.id,
                "name": u.name,
                "email": u.email,
                "role": u.role,
                "is_active": u.is_active
            } for u in users]
        else:
            # Sales manager sees only themselves
            return [{
                "id": current_user.id,
                "name": current_user.name,
                "email": current_user.email,
                "role": current_user.role,
                "is_active": current_user.is_active
            }]
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to fetch users: {str(e)}")


# Optional: Export endpoint
@app.get("/reports/sales-performance/export")
async def export_sales_performance_report(
    period: str = "weekly",
    user_id: Optional[int] = None,
    date: Optional[str] = None,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Export sales performance report as CSV
    """
    from fastapi.responses import StreamingResponse
    import io
    
    # Get the report data
    report_data = await get_sales_performance_report(period, user_id, date, current_user, db)
    
    # Create CSV content with detailed columns
    csv_content = "Sales Rep,Calls Dialed,Calls Answered,Answer Rate,Demos Scheduled,Demos Completed,Completion Rate,Revenue Generated,Activities\n"
    
    for member in report_data['team_performance']:
        answer_rate = member['calls_dialed'] > 0 and round((member['calls_answered'] / member['calls_dialed']) * 100, 1) or 0
        completion_rate = member['demos_scheduled'] > 0 and round((member['demos_completed'] / member['demos_scheduled']) * 100, 1) or 0
        
        csv_content += f"{member['name']},{member['calls_dialed']},{member['calls_answered']},{answer_rate}%,{member['demos_scheduled']},{member['demos_completed']},{completion_rate}%,{member['revenue_generated']},{member['activities']}\n"
    
    # Add summary row
    summary = report_data['summary']
    total_answer_rate = summary['total_calls_dialed'] > 0 and round((summary['total_calls_answered'] / summary['total_calls_dialed']) * 100, 1) or 0
    total_completion_rate = summary['total_demos_scheduled'] > 0 and round((summary['total_demos_completed'] / summary['total_demos_scheduled']) * 100, 1) or 0
    
    csv_content += f"\nTOTAL,{summary['total_calls_dialed']},{summary['total_calls_answered']},{total_answer_rate}%,{summary['total_demos_scheduled']},{summary['total_demos_completed']},{total_completion_rate}%,{summary['total_revenue']},{summary['total_activities']}\n"
    
    # Create streaming response
    return StreamingResponse(
        io.StringIO(csv_content),
        media_type="text/csv",
        headers={
            "Content-Disposition": f"attachment; filename=sales-report-{period}-{datetime.utcnow().strftime('%Y%m%d')}.csv"
        }
    )
    
# with this improved version that explicitly handles all roles including SALES_REP

from pydantic import BaseModel
from typing import Optional
from datetime import datetime

# Pydantic model for updating communication
class CommunicationUpdate(BaseModel):
    subject: Optional[str] = None
    status: Optional[str] = None
    content: Optional[str] = None
    scheduled_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None

@app.put("/communications/{communication_id}")
async def update_communication(
    communication_id: int,
    update_data: CommunicationUpdate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Update a communication (call, email, meeting, etc.)
    
    Permissions:
    - ADMIN: Can edit any communication
    - SALES_MANAGER: Can edit their own communications
    - SALES_REP: Can edit their own communications
    """
    try:
        # Get the communication
        comm = db.query(Communication).filter(Communication.id == communication_id).first()
        
        if not comm:
            raise HTTPException(status_code=404, detail="Communication not found")
        
        # ✅ SIMPLIFIED PERMISSION CHECK - Works for all roles
        # User can edit if they created it OR if they're an admin
        can_edit = (comm.user_id == current_user.id) or PermissionChecker.is_admin(current_user)
        
        if not can_edit:
            raise HTTPException(
                status_code=403, 
                detail="You don't have permission to edit this communication"
            )
        
        # Update fields if provided
        if update_data.subject is not None:
            comm.subject = update_data.subject
        
        if update_data.status is not None:
            comm.status = update_data.status
            # If status is completed/held, set completed_at if not already set
            if update_data.status.lower() in ['completed', 'held'] and not comm.completed_at:
                comm.completed_at = datetime.utcnow()
        
        if update_data.content is not None:
            comm.content = update_data.content
        
        if update_data.scheduled_at is not None:
            comm.scheduled_at = update_data.scheduled_at
        
        if update_data.completed_at is not None:
            comm.completed_at = update_data.completed_at
        
        db.commit()
        db.refresh(comm)

        # Log timeline action
        lead = db.query(Lead).filter(Lead.id == comm.lead_id).first()
        lead_name = f"{lead.first_name} {lead.last_name}" if lead else "Unknown"
        changes = {
            "status": {
                "old": "pending",  # Use the previous status if available
                "new": comm.status
            }
        }
        TimelineLogger.log_communication_updated(db, current_user, comm, lead_name, changes)


        return {
            'id': comm.id,
            'lead_id': comm.lead_id,
            'type': comm.type,
            'subject': comm.subject,
            'content': comm.content,
            'status': comm.status,
            'scheduled_at': comm.scheduled_at,
            'completed_at': comm.completed_at,
            'created_at': comm.created_at,
            'message': 'Communication updated successfully'
        }
        
    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        print(f"Error updating communication: {str(e)}")
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Failed to update communication: {str(e)}")

# Optional: Delete communication endpoint
@app.delete("/communications/{communication_id}")
async def delete_communication(
    communication_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Delete a communication
    """
    try:
        # Get the communication
        comm = db.query(Communication).filter(Communication.id == communication_id).first()
        
        if not comm:
            raise HTTPException(status_code=404, detail="Communication not found")
        
        # Check permissions - user must be the creator or an admin
        if comm.user_id != current_user.id and not PermissionChecker.is_admin(current_user):
            raise HTTPException(status_code=403, detail="You don't have permission to delete this communication")
        
        lead = db.query(Lead).filter(Lead.id == comm.lead_id).first()
        lead_name = f"{lead.first_name} {lead.last_name}" if lead else "Unknown"
        comm_id = comm.id
        comm_type = comm.type
        subject = comm.subject
        
        db.delete(comm)
        db.commit()

        TimelineLogger.log_communication_deleted(db, current_user, comm_id, comm_type, subject, lead_name)

        
        return {"message": "Communication deleted successfully"}
        
    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        print(f"Error deleting communication: {str(e)}")
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Failed to delete communication: {str(e)}")

    # Add these two endpoints to main.py (after other communication endpoints)

@app.get("/communications")
async def get_all_communications(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Get all communications that the current user has access to
    """
    try:
        if PermissionChecker.is_admin(current_user):
            # Admin sees all communications
            comms = db.query(Communication).all()
            return [{
                "id": c.id,
                "lead_id": c.lead_id,
                "user_id": c.user_id,
                "type": c.type,
                "subject": c.subject,
                "content": c.content,
                "scheduled_at": c.scheduled_at,
                "completed_at": c.completed_at,
                "status": c.status,
                "feedback": c.feedback,
                "meet_link": c.meet_link,
                "google_event_id": c.google_event_id,
                "google_message_id": c.google_message_id,
                "created_at": c.created_at
            } for c in comms]
        else:
            # Sales manager sees communications for leads assigned to them
            leads = db.query(Lead).filter(Lead.assigned_to == current_user.id).all()
            lead_ids = [lead.id for lead in leads]
            
            comms = db.query(Communication).filter(Communication.lead_id.in_(lead_ids)).all()
            return [{
                "id": c.id,
                "lead_id": c.lead_id,
                "user_id": c.user_id,
                "type": c.type,
                "subject": c.subject,
                "content": c.content,
                "scheduled_at": c.scheduled_at,
                "completed_at": c.completed_at,
                "status": c.status,
                "feedback": c.feedback,
                "meet_link": c.meet_link,
                "google_event_id": c.google_event_id,
                "google_message_id": c.google_message_id,
                "created_at": c.created_at
            } for c in comms]
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to fetch communications: {str(e)}")

@app.get("/attachments")
async def get_all_attachments(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Get all attachments that the current user has access to
    """
    try:
        if PermissionChecker.is_admin(current_user):
            # Admin sees all attachments
            attachments = db.query(FileAttachment).all()
            return [{
                "id": a.id,
                "lead_id": a.lead_id,
                "user_id": a.user_id,
                "filename": a.filename,
                "original_filename": a.original_filename,
                "file_path": a.file_path,
                "file_size": a.file_size,
                "mime_type": a.mime_type,
                "communication_id": a.communication_id,
                "created_at": a.created_at
            } for a in attachments]
        else:
            # Sales manager sees attachments for leads assigned to them
            leads = db.query(Lead).filter(Lead.assigned_to == current_user.id).all()
            lead_ids = [lead.id for lead in leads]
            
            attachments = db.query(FileAttachment).filter(FileAttachment.lead_id.in_(lead_ids)).all()
            return [{
                "id": a.id,
                "lead_id": a.lead_id,
                "user_id": a.user_id,
                "filename": a.filename,
                "original_filename": a.original_filename,
                "file_path": a.file_path,
                "file_size": a.file_size,
                "mime_type": a.mime_type,
                "communication_id": a.communication_id,
                "created_at": a.created_at
            } for a in attachments]
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to fetch attachments: {str(e)}")
  
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)