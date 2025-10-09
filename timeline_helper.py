# timeline_helper.py - Helper functions for logging actions

from sqlalchemy.orm import Session
from models import ActionTimeline, User
from datetime import datetime
from typing import Optional, Dict, Any

class TimelineLogger:
    """Centralized logger for all CRM actions"""
    
    @staticmethod
    def log_action(
        db: Session,
        user: User,
        action_type: str,
        entity_type: str,
        entity_id: int,
        description: str,
        details: Optional[Dict[str, Any]] = None,
        ip_address: Optional[str] = None
    ) -> ActionTimeline:
        """
        Log an action to the timeline
        
        Args:
            db: Database session
            user: User who performed the action
            action_type: Type of action (CREATE, UPDATE, DELETE, etc.)
            entity_type: Type of entity (lead, communication, user, etc.)
            entity_id: ID of the entity
            description: Human-readable description
            details: Additional structured data (optional)
            ip_address: IP address of the user (optional)
        """
        timeline_entry = ActionTimeline(
            user_id=user.id,
            user_name=user.name,
            action_type=action_type,
            entity_type=entity_type,
            entity_id=entity_id,
            description=description,
            details=details,
            ip_address=ip_address,
            created_at=datetime.utcnow()
        )
        
        db.add(timeline_entry)
        db.commit()
        db.refresh(timeline_entry)
        return timeline_entry
    
    @staticmethod
    def log_lead_created(db: Session, user: User, lead, ip: str = None):
        """Log lead creation"""
        return TimelineLogger.log_action(
            db, user,
            action_type="CREATE",
            entity_type="lead",
            entity_id=lead.id,
            description=f"Created lead: {lead.first_name} {lead.last_name}",
            details={
                "lead_name": f"{lead.first_name} {lead.last_name}",
                "email": lead.email_address,
                "status": lead.status,
                "source": lead.lead_source
            },
            ip_address=ip
        )
    
    @staticmethod
    def log_lead_updated(db: Session, user: User, lead, changed_fields: Dict, ip: str = None):
        """Log lead update"""
        changes_desc = ", ".join([f"{k}: {v['old']} → {v['new']}" for k, v in changed_fields.items()])
        return TimelineLogger.log_action(
            db, user,
            action_type="UPDATE",
            entity_type="lead",
            entity_id=lead.id,
            description=f"Updated lead: {lead.first_name} {lead.last_name} - {changes_desc}",
            details={"changes": changed_fields},
            ip_address=ip
        )
    
    @staticmethod
    def log_lead_deleted(db: Session, user: User, lead_id: int, lead_name: str, ip: str = None):
        """Log lead deletion"""
        return TimelineLogger.log_action(
            db, user,
            action_type="DELETE",
            entity_type="lead",
            entity_id=lead_id,
            description=f"Deleted lead: {lead_name}",
            details={"lead_name": lead_name},
            ip_address=ip
        )
    
    @staticmethod
    def log_lead_status_change(db: Session, user: User, lead, old_status: str, new_status: str, ip: str = None):
        """Log lead status change"""
        return TimelineLogger.log_action(
            db, user,
            action_type="STATUS_CHANGE",
            entity_type="lead",
            entity_id=lead.id,
            description=f"Changed status of {lead.first_name} {lead.last_name}: {old_status} → {new_status}",
            details={
                "old_status": old_status,
                "new_status": new_status,
                "lead_name": f"{lead.first_name} {lead.last_name}"
            },
            ip_address=ip
        )
    
    @staticmethod
    def log_lead_assigned(db: Session, user: User, lead, assigned_to_name: str, ip: str = None):
        """Log lead assignment"""
        return TimelineLogger.log_action(
            db, user,
            action_type="ASSIGN",
            entity_type="lead",
            entity_id=lead.id,
            description=f"Assigned {lead.first_name} {lead.last_name} to {assigned_to_name}",
            details={
                "lead_name": f"{lead.first_name} {lead.last_name}",
                "assigned_to": assigned_to_name
            },
            ip_address=ip
        )
    
    @staticmethod
    def log_communication_created(db: Session, user: User, comm, lead_name: str, ip: str = None):
        """Log communication creation"""
        comm_type_map = {
            "email": "Email",
            "meeting": "Meeting",
            "call": "Call",
            "note": "Note"
        }
        comm_type_label = comm_type_map.get(comm.type, comm.type)
        
        return TimelineLogger.log_action(
            db, user,
            action_type="CREATE",
            entity_type="communication",
            entity_id=comm.id,
            description=f"Created {comm_type_label}: {comm.subject} for {lead_name}",
            details={
                "communication_type": comm.type,
                "subject": comm.subject,
                "lead_name": lead_name,
                "status": comm.status
            },
            ip_address=ip
        )
    
    @staticmethod
    def log_communication_updated(db: Session, user: User, comm, lead_name: str, changes: Dict, ip: str = None):
        """Log communication update"""
        return TimelineLogger.log_action(
            db, user,
            action_type="UPDATE",
            entity_type="communication",
            entity_id=comm.id,
            description=f"Updated {comm.type}: {comm.subject} for {lead_name}",
            details={
                "communication_type": comm.type,
                "subject": comm.subject,
                "lead_name": lead_name,
                "changes": changes
            },
            ip_address=ip
        )
    
    @staticmethod
    def log_user_created(db: Session, user: User, new_user, ip: str = None):
        """Log user creation"""
        return TimelineLogger.log_action(
            db, user,
            action_type="CREATE",
            entity_type="user",
            entity_id=new_user.id,
            description=f"Created user: {new_user.name} ({new_user.role})",
            details={
                "user_name": new_user.name,
                "email": new_user.email,
                "role": new_user.role
            },
            ip_address=ip
        )
    
    @staticmethod
    def log_user_status_change(db: Session, user: User, target_user_id: int, target_user_name: str, is_active: bool, ip: str = None):
        """Log user activation/deactivation"""
        action = "activated" if is_active else "deactivated"
        return TimelineLogger.log_action(
            db, user,
            action_type="STATUS_CHANGE",
            entity_type="user",
            entity_id=target_user_id,
            description=f"{action.capitalize()} user: {target_user_name}",
            details={
                "user_name": target_user_name,
                "is_active": is_active
            },
            ip_address=ip
        )

    @staticmethod
    def log_email_sent(db: Session, user: User, lead, subject: str, ip: str = None):
        """Log email sent"""
        return TimelineLogger.log_action(
            db, user,
            action_type="EMAIL_SENT",
            entity_type="lead",
            entity_id=lead.id,
            description=f"Sent email to {lead.first_name} {lead.last_name}: {subject}",
            details={
                "lead_name": f"{lead.first_name} {lead.last_name}",
                "subject": subject,
                "email": lead.email_address
            },
            ip_address=ip
        )
    
    @staticmethod
    def log_meeting_scheduled(db: Session, user: User, lead, subject: str, scheduled_time: str, ip: str = None):
        """Log meeting scheduled"""
        return TimelineLogger.log_action(
            db, user,
            action_type="MEETING_SCHEDULED",
            entity_type="lead",
            entity_id=lead.id,
            description=f"Scheduled meeting with {lead.first_name} {lead.last_name}: {subject}",
            details={
                "lead_name": f"{lead.first_name} {lead.last_name}",
                "subject": subject,
                "scheduled_at": scheduled_time
            },
            ip_address=ip
        )