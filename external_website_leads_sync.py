# external_website_leads_sync.py - FIXED VERSION
# Handles created_at properly and better error handling

from fastapi import APIRouter, HTTPException, Depends
from sqlalchemy.orm import Session
from sqlalchemy import text
from datetime import datetime
from typing import List, Dict
import logging

# Import from database config (avoids circular import)
from database import get_db, external_engine

# Your CRM models
from models import Lead, LeadSource, LeadStatus

router = APIRouter(prefix="/api/external-leads", tags=["External Website Leads"])
logger = logging.getLogger(__name__)


# ==========================================
# STEP 1: Create State Table in YOUR CRM DB
# ==========================================
"""
Run this SQL in YOUR CRM database (not the external one):

CREATE TABLE IF NOT EXISTS fetch_state (
    id INT AUTO_INCREMENT PRIMARY KEY,
    source_name VARCHAR(100) UNIQUE NOT NULL,
    last_fetched_id BIGINT DEFAULT 0,
    last_fetched_at TIMESTAMP NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

INSERT INTO fetch_state (source_name, last_fetched_id) 
VALUES ('external_website_leads', 0)
ON DUPLICATE KEY UPDATE source_name = source_name;
"""


# ==========================================
# STEP 2: Fetch and Sync New Leads
# ==========================================

@router.post("/sync-website-leads", response_model=Dict)
async def sync_external_website_leads(db: Session = Depends(get_db)):
    """
    Fetch NEW leads from external website database and store them in CRM.
    Only fetches leads that haven't been synced before.
    """
    external_conn = None
    
    try:
        source_name = "external_website_leads"
        
        # 1️⃣ Get last fetched ID from YOUR CRM database
        result = db.execute(
            text("SELECT last_fetched_id FROM fetch_state WHERE source_name = :source"),
            {"source": source_name}
        ).fetchone()
        
        if not result:
            # Initialize if not exists
            db.execute(
                text("INSERT INTO fetch_state (source_name, last_fetched_id) VALUES (:source, 0)"),
                {"source": source_name}
            )
            db.commit()
            last_fetched_id = 0
        else:
            last_fetched_id = result[0]
        
        logger.info(f"📊 Last fetched external lead ID: {last_fetched_id}")
        
        # 2️⃣ Connect to EXTERNAL database and fetch NEW leads
        external_conn = external_engine.connect()
        
        # Fetch from external website database
        # Mapping: full_name → first_name/last_name, email → email_address, 
        # chosen_field → course_interested_in, phone_number → mobile_number
        query = text("""
            SELECT 
                id,
                full_name,
                email,
                chosen_field,
                phone_number,
                created_at
            FROM new_contacts
            WHERE id > :last_id
            ORDER BY id ASC
            LIMIT 500
        """)
        
        external_leads = external_conn.execute(
            query, 
            {"last_id": last_fetched_id}
        ).fetchall()
        
        if not external_leads:
            return {
                "success": True,
                "message": "✅ No new website leads found",
                "synced_count": 0,
                "last_fetched_id": last_fetched_id
            }
        
        logger.info(f"🔍 Found {len(external_leads)} new leads in external DB")
        
        # 3️⃣ Insert NEW leads into YOUR CRM leads table
        synced_leads = []
        skipped_leads = []
        error_leads = []
        new_last_id = last_fetched_id
        
        for ext_lead in external_leads:
            try:
                # Check if email already exists in YOUR CRM (prevent duplicates)
                existing = db.query(Lead).filter(
                    Lead.email_address == ext_lead.email
                ).first()
                
                if existing:
                    logger.warning(f"⚠️ Lead with email {ext_lead.email} already exists, skipping")
                    skipped_leads.append({
                        "external_id": ext_lead.id,
                        "email": ext_lead.email,
                        "reason": "duplicate_email"
                    })
                    new_last_id = ext_lead.id  # Update ID even for skipped leads
                    continue
                
                # Split full_name into first_name and last_name
                full_name = (ext_lead.full_name or "").strip()
                name_parts = full_name.split(" ", 1)  # Split at first space
                first_name = name_parts[0] if len(name_parts) > 0 and name_parts[0] else "Unknown"
                last_name = name_parts[1] if len(name_parts) > 1 else "Lead"
                
                # Create new lead in YOUR CRM with correct column mapping
                # DON'T pass created_at in constructor - it's auto-generated
                new_lead = Lead(
                    first_name=first_name,
                    last_name=last_name,
                    email_address=ext_lead.email,
                    mobile_number=ext_lead.phone_number or "",
                    course_interested_in=ext_lead.chosen_field,
                    lead_source="Website",
                    status="New"
                )
                
                db.add(new_lead)
                db.flush()  # Flush to get the ID but don't commit yet
                
                # NOW set created_at after the object is created (if you want to preserve original date)
                if hasattr(ext_lead, 'created_at') and ext_lead.created_at:
                    new_lead.created_at = ext_lead.created_at
                
                synced_leads.append({
                    "external_id": ext_lead.id,
                    "crm_id": new_lead.id,
                    "name": full_name,
                    "email": ext_lead.email,
                    "course": ext_lead.chosen_field
                })
                
                new_last_id = ext_lead.id
                
            except Exception as lead_error:
                error_msg = str(lead_error)
                logger.error(f"❌ Error processing lead {ext_lead.id}: {error_msg}")
                error_leads.append({
                    "external_id": ext_lead.id,
                    "email": getattr(ext_lead, 'email', 'unknown'),
                    "error": error_msg
                })
                # Continue processing other leads
                continue
        
        # 4️⃣ Commit all new leads to YOUR CRM database
        if synced_leads:
            try:
                db.commit()
                logger.info(f"✅ Successfully committed {len(synced_leads)} new leads")
            except Exception as commit_error:
                logger.error(f"❌ Error committing leads: {str(commit_error)}")
                db.rollback()
                raise HTTPException(
                    status_code=500,
                    detail=f"Failed to commit leads to database: {str(commit_error)}"
                )
        
        # 5️⃣ Update the last fetched ID in state table
        if synced_leads or skipped_leads:
            db.execute(
                text("""
                    UPDATE fetch_state 
                    SET last_fetched_id = :new_id, 
                        last_fetched_at = :now
                    WHERE source_name = :source
                """),
                {
                    "new_id": new_last_id,
                    "now": datetime.utcnow(),
                    "source": source_name
                }
            )
            db.commit()
        
        logger.info(f"✅ Sync completed: {len(synced_leads)} synced, {len(skipped_leads)} skipped, {len(error_leads)} errors")
        
        return {
            "success": True,
            "message": f"✅ Sync completed",
            "synced_count": len(synced_leads),
            "skipped_count": len(skipped_leads),
            "error_count": len(error_leads),
            "last_fetched_id": new_last_id,
            "synced_leads": synced_leads[:10],  # First 10 only
            "skipped_leads": skipped_leads[:5] if skipped_leads else [],
            "errors": error_leads[:5] if error_leads else []
        }
        
    except Exception as e:
        logger.error(f"❌ Error syncing external leads: {str(e)}")
        db.rollback()
        raise HTTPException(
            status_code=500,
            detail=f"Failed to sync external website leads: {str(e)}"
        )
    
    finally:
        if external_conn:
            external_conn.close()


# ==========================================
# STEP 3: Check Sync Status
# ==========================================

@router.get("/sync-status", response_model=Dict)
async def get_sync_status(db: Session = Depends(get_db)):
    """Check how many leads are pending sync"""
    external_conn = None
    
    try:
        # Get last fetched ID from CRM
        result = db.execute(
            text("SELECT last_fetched_id, last_fetched_at FROM fetch_state WHERE source_name = 'external_website_leads'")
        ).fetchone()
        
        last_id = result[0] if result else 0
        last_sync = result[1] if result else None
        
        # Count pending leads in external DB
        external_conn = external_engine.connect()
        pending = external_conn.execute(
            text("SELECT COUNT(*) FROM Resumes WHERE id > :last_id"),
            {"last_id": last_id}
        ).scalar()
        
        # Count total website leads in YOUR CRM
        total_in_crm = db.query(Lead).filter(Lead.lead_source == "Website").count()
        
        return {
            "success": True,
            "last_synced_id": last_id,
            "last_synced_at": last_sync.isoformat() if last_sync else None,
            "pending_leads": pending,
            "total_website_leads_in_crm": total_in_crm
        }
        
    except Exception as e:
        logger.error(f"Error getting sync status: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        if external_conn:
            external_conn.close()


# ==========================================
# STEP 4: Manual Trigger (Optional)
# ==========================================

@router.post("/trigger-sync")
async def trigger_manual_sync(db: Session = Depends(get_db)):
    """Manually trigger a sync - useful for testing"""
    return await sync_external_website_leads(db)


# ==========================================
# STEP 5: Reset Sync (Admin Only - Use Carefully!)
# ==========================================

@router.post("/reset-sync", response_model=Dict)
async def reset_sync_state(db: Session = Depends(get_db)):
    """
    ⚠️ ADMIN ONLY: Reset the sync state to re-fetch all website leads.
    Use this carefully - it will process all website leads again!
    """
    try:
        db.execute(
            text("""
                UPDATE fetch_state 
                SET last_fetched_id = 0,
                    last_fetched_at = NULL
                WHERE source_name = 'external_website_leads'
            """)
        )
        db.commit()
        
        return {
            "success": True,
            "message": "⚠️ Sync state has been reset. Next sync will process all website leads."
        }
        
    except Exception as e:
        logger.error(f"Error resetting sync state: {str(e)}")
        db.rollback()
        raise HTTPException(
            status_code=500,
            detail=f"Failed to reset sync state: {str(e)}"
        )