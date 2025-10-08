# migrate_database.py - Fix lead_source and status columns
import pymysql
import os
from dotenv import load_dotenv
import urllib.parse

load_dotenv()

# Database configuration
DATABASE_URL="mysql+pymysql://root:Kiran%40123@localhost:3306/edtech_crm"

# Extract connection details from DATABASE_URL
# Format: mysql+pymysql://user:password@host/database
if DATABASE_URL.startswith('mysql+pymysql://'):
    url_part = DATABASE_URL.replace('mysql+pymysql://', '')
    if '@' in url_part:
        auth_part, host_db_part = url_part.split('@', 1)
        if ':' in auth_part:
            username, password = auth_part.split(':', 1)
            password = urllib.parse.unquote(password)  # <-- decode %40 into @
        else:
            username, password = auth_part, ''
        if '/' in host_db_part:
            host_port, database = host_db_part.split('/', 1)
            if ':' in host_port:
                host, port = host_port.split(':', 1)
                port = int(port)
            else:
                host, port = host_port, 3306
        else:
            host, port, database = host_db_part, 3306, 'edtech_crm'
    else:
        # Fallback values
        username, password, host, port, database = 'user', 'password', 'localhost', 3306, 'edtech_crm'
else:
    # Fallback values
    username, password, host, port, database = 'user', 'password', 'localhost', 3306, 'edtech_crm'

def migrate_database():
    """Fix the lead_source and status columns in the leads table"""
    
    try:
        # Connect to the database
        connection = pymysql.connect(
            host=host,
            port=port,
            user=username,
            password=password,
            database=database,
            charset='utf8mb4'
        )
        
        with connection.cursor() as cursor:
            print("Connected to database successfully!")
            
            # Check current table structure
            print("\n1. Checking current table structure...")
            cursor.execute("DESCRIBE leads")
            columns = cursor.fetchall()
            
            for column in columns:
                if column[0] in ['lead_source', 'status']:
                    print(f"   {column[0]}: {column[1]}")
            
            # Modify lead_source column
            print("\n2. Updating lead_source column...")
            alter_lead_source = """
            ALTER TABLE leads 
            MODIFY COLUMN lead_source VARCHAR(50) NULL
            """
            cursor.execute(alter_lead_source)
            print("   ✓ lead_source column updated to VARCHAR(50)")
            
            # Modify status column
            print("\n3. Updating status column...")
            alter_status = """
            ALTER TABLE leads 
            MODIFY COLUMN status VARCHAR(20) NULL DEFAULT 'New'
            """
            cursor.execute(alter_status)
            print("   ✓ status column updated to VARCHAR(20)")
            
            # Update any existing enum values to string values
            print("\n4. Converting existing enum values...")
            
            # Map enum values to display values for lead_source
            lead_source_updates = [
                ("COLD_CALL", "Cold Call"),
                ("EXISTING_CUSTOMER", "Existing Customer"),
                ("SELF_GENERATED", "Self Generated"),
                ("EMPLOYEE", "Employee"),
                ("PARTNER", "Partner"),
                ("PUBLIC_RELATIONS", "Public Relations"),
                ("DIRECT_MAIL", "Direct Mail"),
                ("CONFERENCE", "Conference"),
                ("TRADE_SHOW", "Trade Show"),
                ("WEBSITE", "Website"),
                ("WORD_OF_MOUTH", "Word of Mouth"),
                ("EMAIL", "Email"),
                ("CAMPAIGN", "Campaign"),
                ("OTHER", "Other")
            ]
            
            for old_val, new_val in lead_source_updates:
                cursor.execute(
                    "UPDATE leads SET lead_source = %s WHERE lead_source = %s",
                    (new_val, old_val)
                )
                affected = cursor.rowcount
                if affected > 0:
                    print(f"   ✓ Updated {affected} records: {old_val} → {new_val}")
            
            # Map enum values to display values for status
            status_updates = [
                ("NEW", "New"),
                ("ASSIGNED", "Assigned"),
                ("IN_PROCESS", "In Process"),
                ("CONVERTED", "Converted"),
                ("RECYCLED", "Recycled"),
                ("DEAD", "Dead")
            ]
            
            for old_val, new_val in status_updates:
                cursor.execute(
                    "UPDATE leads SET status = %s WHERE status = %s",
                    (new_val, old_val)
                )
                affected = cursor.rowcount
                if affected > 0:
                    print(f"   ✓ Updated {affected} records: {old_val} → {new_val}")
            
            # Commit all changes
            connection.commit()
            print("\n5. All changes committed successfully!")
            
            # Verify the changes
            print("\n6. Verification:")
            cursor.execute("SELECT DISTINCT lead_source FROM leads WHERE lead_source IS NOT NULL")
            sources = [row[0] for row in cursor.fetchall()]
            print(f"   Lead sources in database: {sources}")
            
            cursor.execute("SELECT DISTINCT status FROM leads WHERE status IS NOT NULL")
            statuses = [row[0] for row in cursor.fetchall()]
            print(f"   Statuses in database: {statuses}")
            
            print("\n✅ Database migration completed successfully!")
            
    except Exception as e:
        print(f"❌ Error during migration: {e}")
        if 'connection' in locals():
            connection.rollback()
        raise
    finally:
        if 'connection' in locals():
            connection.close()
            print("Database connection closed.")

if __name__ == "__main__":
    print("Starting database migration...")
    print(f"Host: {host}:{port}")
    print(f"Database: {database}")
    print(f"Username: {username}")
    print("-" * 50)
    
    migrate_database()
    
    print("\n" + "="*50)
    print("Migration completed! You can now:")
    print("1. Restart your FastAPI server")
    print("2. Try creating leads again")
    print("3. The lead_source and status columns now accept string values")
    print("="*50)