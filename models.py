# models.py - Fixed Data Models with Proper Enum Handling
import enum
from sqlalchemy import Column, Integer, String, DateTime, Text, ForeignKey, Boolean, Enum, Float, func, JSON
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from pydantic import BaseModel, EmailStr, validator
from datetime import datetime
from typing import Optional
from enum import Enum as PyEnum


Base = declarative_base()

# Updated Enums - Using shorter, database-friendly values
class UserRole(str, PyEnum):
    ADMIN = "ADMIN"
    SALES_MANAGER = "SALES_MANAGER"
    SALES_REP = "SALES_REP"

class LeadSource(str, PyEnum):
    COLD_CALL = "Cold Call"
    EXISTING_CUSTOMER = "Existing Customer"
    SELF_GENERATED = "Self Generated"
    EMPLOYEE = "Employee"
    PARTNER = "Partner"
    PUBLIC_RELATIONS = "Public Relations"
    DIRECT_MAIL = "Direct Mail"
    CONFERENCE = "Conference"
    TRADE_SHOW = "Trade Show"
    WEBSITE = "Website"
    WORD_OF_MOUTH = "Word of Mouth"
    EMAIL = "Email"
    CAMPAIGN = "Campaign"
    OTHER = "Other"

class LeadStatus(str, PyEnum):
    NEW = "New"
    ASSIGNED = "Assigned"
    IN_PROCESS = "In Process"
    CONVERTED = "Converted"
    RECYCLED = "Recycled"
    DEAD = "Dead"

# Add to your existing models.py
from sqlalchemy import Column, Integer, String, DateTime, Text, ForeignKey, Boolean, LargeBinary
import os
from datetime import datetime

class FileAttachment(Base):
    """File attachments for email communications"""
    __tablename__ = "file_attachments"
    
    id = Column(Integer, primary_key=True, index=True)
    filename = Column(String(500), nullable=False)
    original_filename = Column(String(500), nullable=False)
    file_path = Column(String(1000), nullable=False)
    file_size = Column(Integer, nullable=False)
    mime_type = Column(String(255), nullable=False)
    communication_id = Column(Integer, ForeignKey('communications.id'), nullable=True)
    lead_id = Column(Integer, ForeignKey('leads.id'), nullable=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    communication = relationship("Communication", back_populates="attachments")
    lead = relationship("Lead", back_populates="attachments")
    user = relationship("User")

# Update Communication model to include attachments
class Communication(Base):
    __tablename__ = "communications"
    
    id = Column(Integer, primary_key=True, index=True)
    lead_id = Column(Integer, ForeignKey('leads.id'))
    user_id = Column(Integer, ForeignKey('users.id'))
    type = Column(String(50))  # email, meeting, call, note
    subject = Column(String(500))
    content = Column(Text)
    scheduled_at = Column(DateTime)
    completed_at = Column(DateTime)
    status = Column(String(50))  # scheduled, completed, cancelled
    feedback = Column(Text, nullable=True)  # New field to store admin feedback
    google_event_id = Column(String(500))
    google_message_id = Column(String(500))
    meet_link = Column(String(1000))
    audio_url = Column(String(1000), nullable=True)
    details = Column(JSON, nullable=True)          # or Column(Text, nullable=True)
    call_type = Column(String(50), nullable=True)
    call_duration = Column(Integer, nullable=True)
    lead_status = Column(String(50), nullable=True)
    reminder_15_sent = Column(Boolean, default=False, nullable=False)
    reminder_10_sent = Column(Boolean, default=False, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    
    # Add this relationship
    attachments = relationship("FileAttachment", back_populates="communication")
    lead = relationship("Lead", back_populates="communications")
    user = relationship("User")

# Database Models
class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String(255), unique=True, index=True)
    name = Column(String(255))
    hashed_password = Column(String(255))
    role = Column(Enum(UserRole), default=UserRole.SALES_MANAGER)
    is_active = Column(Boolean, default=True)
    admin_id = Column(Integer, nullable=True)
    monthly_target = Column(Integer, default=0)
    created_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=True)

    leads = relationship("Lead", back_populates="assigned_sales_manager", foreign_keys="[Lead.assigned_to]")

class Lead(Base):
    __tablename__ = "leads"

    id = Column(Integer, primary_key=True, index=True)
    salutation = Column(String(50), nullable=True)
    first_name = Column(String(255), nullable=False)
    last_name = Column(String(255), nullable=False)
    mobile_number = Column(String(50), nullable=False)
    alternate_mobile_number = Column(String(50), nullable=True)
    email_address = Column(String(255), nullable=False)
    working_status = Column(String(50), nullable=True)
    street = Column(String(255), nullable=True)
    postal_code = Column(String(20), nullable=True)
    city = Column(String(100), nullable=True)
    state = Column(String(100), nullable=True)
    country = Column(String(100), nullable=True)
    institute_name = Column(String(255), nullable=True)
    qualification = Column(String(255), nullable=True)
    course_interested_in = Column(String(255), nullable=True)
    description = Column(Text, nullable=True)
    opportunity_amount = Column(Float, nullable=True)
    # Store as string instead of enum to avoid truncation
    lead_source = Column(String(50), nullable=True)  # Changed from Enum to String
    referred_by = Column(String(255), nullable=True)
    status = Column(String(20), nullable=True, default="New")  # Changed from Enum to String
    status_description = Column(Text, nullable=True)
    created_at = Column(DateTime, default=func.now(), nullable=True)
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now(), nullable=True)
    assigned_to = Column(Integer, ForeignKey("users.id"), nullable=True)

    assigned_sales_manager = relationship("User", back_populates="leads")
    attachments = relationship("FileAttachment", back_populates="lead")
    communications = relationship("Communication", back_populates="lead")

# Google Workspace Integration Models
class GoogleToken(Base):
    __tablename__ = "google_tokens"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), unique=True)
    token = Column(Text, nullable=False)
    refresh_token = Column(Text, nullable=True)
    token_uri = Column(String(255), nullable=False)
    client_id = Column(String(255), nullable=False)
    client_secret = Column(String(255), nullable=False)
    scopes = Column(Text, nullable=False)  # JSON array as string
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

# Add this to models.py

from sqlalchemy import Column, Integer, String, DateTime, Text, ForeignKey, JSON
from datetime import datetime

class ActionTimeline(Base):
    """Tracks all CRUD operations and major actions across the CRM"""
    __tablename__ = "action_timeline"
    
    id = Column(Integer, primary_key=True, index=True)
    
    # Who performed the action
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    user_name = Column(String(255), nullable=False)  # Denormalized for performance
    
    # What was done
    action_type = Column(String(50), nullable=False)  # CREATE, UPDATE, DELETE, STATUS_CHANGE, ASSIGN, etc.
    entity_type = Column(String(50), nullable=False)  # lead, communication, user, etc.
    entity_id = Column(Integer, nullable=False)
    
    # Details about the action
    description = Column(Text, nullable=False)  # Human-readable description
    details = Column(JSON, nullable=True)  # Additional structured data (old_value, new_value, etc.)
    
    # Metadata
    ip_address = Column(String(45), nullable=True)  # IPv4 or IPv6
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    
    # Relationships
    user = relationship("User", foreign_keys=[user_id])

# Pydantic model for creating timeline entries
class TimelineEntryCreate(BaseModel):
    action_type: str
    entity_type: str
    entity_id: int
    description: str
    details: Optional[dict] = None

# Updated Pydantic Models
class LeadCreate(BaseModel):
    # Personal Information (Required)
    first_name: str
    last_name: str
    email_address: EmailStr
    mobile_number: str
    
    # Personal Information (Optional)
    salutation: Optional[str] = None
    alternate_mobile_number: Optional[str] = None
    working_status: Optional[str] = None
    
    # Address Information
    street: Optional[str] = None
    postal_code: Optional[str] = None
    city: Optional[str] = None
    state: Optional[str] = None
    country: Optional[str] = None
    
    # Educational / Professional Information
    institute_name: Optional[str] = None
    qualification: Optional[str] = None
    course_interested_in: Optional[str] = None
    
    # Lead Details
    description: Optional[str] = None
    opportunity_amount: Optional[float] = None
    lead_source: Optional[str] = None  # Changed to accept string directly
    referred_by: Optional[str] = None
    
    # Lead Status
    status: Optional[str] = "New"  # Changed to accept string directly
    status_description: Optional[str] = None
    
    # User Assignment
    assigned_to: Optional[int] = None

    # Validators
    @validator('first_name', 'last_name')
    def validate_names(cls, v):
        if v:
            v = v.strip()
            if len(v) < 1:
                raise ValueError('Name cannot be empty')
            if len(v) > 255:
                raise ValueError('Name too long')
        return v

    @validator('mobile_number')
    def validate_mobile(cls, v):
        if v:
            v = v.strip()
            if len(v) < 10:
                raise ValueError('Mobile number too short')
            if len(v) > 15:
                raise ValueError('Mobile number too long')
        return v

    @validator('opportunity_amount')
    def validate_amount(cls, v):
        if v is not None and v < 0:
            raise ValueError('Opportunity amount cannot be negative')
        return v

    @validator('lead_source')
    def validate_lead_source(cls, v):
        if v:
            # Accept both enum values and string values
            valid_sources = [
                "Cold Call", "Existing Customer", "Self Generated", "Employee",
                "Partner", "Public Relations", "Direct Mail", "Conference",
                "Trade Show", "Website", "Word of Mouth", "Email", "Campaign", "Other"
            ]
            if v not in valid_sources:
                # If it's not a valid display value, try to map it
                source_mapping = {
                    "COLD_CALL": "Cold Call",
                    "EXISTING_CUSTOMER": "Existing Customer",
                    "SELF_GENERATED": "Self Generated",
                    "EMPLOYEE": "Employee",
                    "PARTNER": "Partner",
                    "PUBLIC_RELATIONS": "Public Relations",
                    "DIRECT_MAIL": "Direct Mail",
                    "CONFERENCE": "Conference",
                    "TRADE_SHOW": "Trade Show",
                    "WEBSITE": "Website",
                    "WORD_OF_MOUTH": "Word of Mouth",
                    "EMAIL": "Email",
                    "CAMPAIGN": "Campaign",
                    "OTHER": "Other"
                }
                v = source_mapping.get(v, v)
        return v

    @validator('status')
    def validate_status(cls, v):
        if v:
            valid_statuses = ["New", "Assigned", "In Process", "Converted", "Recycled", "Dead"]
            if v not in valid_statuses:
                # Map enum values to display values
                status_mapping = {
                    "NEW": "New",
                    "ASSIGNED": "Assigned",
                    "IN_PROCESS": "In Process",
                    "CONVERTED": "Converted",
                    "RECYCLED": "Recycled",
                    "DEAD": "Dead"
                }
                v = status_mapping.get(v, v)
        return v

class LeadUpdate(BaseModel):
    salutation: Optional[str] = None
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    mobile_number: Optional[str] = None
    alternate_mobile_number: Optional[str] = None
    email_address: Optional[EmailStr] = None
    working_status: Optional[str] = None
    street: Optional[str] = None
    postal_code: Optional[str] = None
    city: Optional[str] = None
    state: Optional[str] = None
    country: Optional[str] = None
    institute_name: Optional[str] = None
    qualification: Optional[str] = None
    course_interested_in: Optional[str] = None
    description: Optional[str] = None
    opportunity_amount: Optional[float] = None
    lead_source: Optional[str] = None  # Changed to string
    referred_by: Optional[str] = None
    status: Optional[str] = None       # Changed to string
    status_description: Optional[str] = None
    assigned_to: Optional[int] = None

    # Validators (same as LeadCreate)
    @validator('first_name', 'last_name')
    def validate_names(cls, v):
        if v and v.strip():
            v = v.strip()
            if len(v) > 255:
                raise ValueError('Name too long')
        return v

    @validator('mobile_number')
    def validate_mobile(cls, v):
        if v and v.strip():
            v = v.strip()
            if len(v) < 10:
                raise ValueError('Mobile number too short')
            if len(v) > 15:
                raise ValueError('Mobile number too long')
        return v

    @validator('opportunity_amount')
    def validate_amount(cls, v):
        if v is not None and v < 0:
            raise ValueError('Opportunity amount cannot be negative')
        return v

class LeadResponse(BaseModel):
    id: int
    salutation: Optional[str]
    first_name: str
    last_name: str
    email_address: str
    mobile_number: str
    alternate_mobile_number: Optional[str]
    working_status: Optional[str]
    street: Optional[str]
    postal_code: Optional[str]
    city: Optional[str]
    state: Optional[str]
    country: Optional[str]
    institute_name: Optional[str]
    qualification: Optional[str]
    course_interested_in: Optional[str]
    description: Optional[str]
    opportunity_amount: Optional[float]
    lead_source: Optional[str]
    referred_by: Optional[str]
    status: str
    status_description: Optional[str]
    assigned_to: Optional[int]
    created_at: Optional[datetime]
    updated_at: Optional[datetime]

    class Config:
        from_attributes = True

class LeadAssignment(BaseModel):
    sales_manager_id: int

class DealCreate(BaseModel):
    title: str
    amount: int
    lead_id: int
    course_licenses: Optional[int] = None
    contract_duration: Optional[int] = None
    expected_close_date: Optional[datetime] = None

class EmailTemplate(Base):
    __tablename__ = "email_templates"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255), nullable=False)  # Template name
    subject = Column(String(500), nullable=False)
    body = Column(Text, nullable=False)
    created_by = Column(Integer, ForeignKey("users.id"))
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    creator = relationship("User")

class WhatsAppTemplate(Base):
    __tablename__ = "whatsapp_templates"

    id = Column(Integer, primary_key=True, index=True)
    title = Column(String(255), nullable=False)
    content = Column(Text, nullable=False)
    created_by = Column(Integer, ForeignKey("users.id"))
    created_at = Column(DateTime, default=datetime.utcnow)



# class ActivityCreate(BaseModel):
#     type: ActivityType
#     subject: str
#     description: Optional[str] = None
#     scheduled_date: Optional[datetime] = None
#     lead_id: Optional[int] = None
#     deal_id: Optional[int] = None