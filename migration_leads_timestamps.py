# migration_leads_timestamps.py
# Run this script to add created_at and updated_at columns to the leads table

import pymysql
import os
from dotenv import load_dotenv
import urllib.parse

load_dotenv()

# Database configuration - using the same pattern as in the existing migration.py
DATABASE_URL = os.getenv("DATABASE_URL", "mysql+pymysql://root:Kiran%40123@localhost:3306/edtech_crm")

# Extract connection details from DATABASE_URL
# Format: mysql+pymysql://user:password@host/database
if DATABASE_URL.startswith('mysql+pymysql://'):
    url_part = DATABASE_URL.replace('mysql+pymysql://', '')
    if '@' in url_part:
        auth_part, host_db_part = url_part.split('@', 1)
        if ':' in auth_part:
            username, password = auth_part.split(':', 1)
            password = urllib.parse.unquote(password)
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

def migrate_leads_add_timestamps():
    """Add created_at and updated_at columns to the leads table using local time"""
    
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
            print("\n1. Checking current leads table structure...")
            cursor.execute("DESCRIBE leads")
            columns = cursor.fetchall()
            
            # Check if columns already exist
            has_created_at = any(col[0] == 'created_at' for col in columns)
            has_updated_at = any(col[0] == 'updated_at' for col in columns)
            
            if has_created_at and has_updated_at:
                print("   ✓ created_at and updated_at columns already exist")
                return
            
            # Add created_at column if it doesn't exist
            if not has_created_at:
                print("\n2. Adding created_at column...")
                # Using CURRENT_TIMESTAMP which is local to the database server's time zone
                add_created_at = """
                ALTER TABLE leads 
                ADD COLUMN created_at TIMESTAMP NULL DEFAULT CURRENT_TIMESTAMP
                """
                cursor.execute(add_created_at)
                print("   ✓ created_at column added successfully")
                
                # Initialize existing records with the current timestamp
                print("   Initializing created_at for existing records...")
                update_existing_created_at = """
                UPDATE leads SET created_at = CURRENT_TIMESTAMP WHERE created_at IS NULL
                """
                cursor.execute(update_existing_created_at)
                print("   ✓ Existing records initialized with created_at timestamp")
            else:
                print("\n2. created_at column already exists - skipping")
            
            # Add updated_at column if it doesn't exist
            if not has_updated_at:
                print("\n3. Adding updated_at column...")
                # Using CURRENT_TIMESTAMP which is local to the database server's time zone
                add_updated_at = """
                ALTER TABLE leads 
                ADD COLUMN updated_at TIMESTAMP NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
                """
                cursor.execute(add_updated_at)
                print("   ✓ updated_at column added successfully")
                
                # Initialize existing records with the current timestamp
                print("   Initializing updated_at for existing records...")
                update_existing_updated_at = """
                UPDATE leads SET updated_at = CURRENT_TIMESTAMP WHERE updated_at IS NULL
                """
                cursor.execute(update_existing_updated_at)
                print("   ✓ Existing records initialized with updated_at timestamp")
            else:
                print("\n3. updated_at column already exists - skipping")
            
            connection.commit()
            print("\nMigration completed successfully!")
            
    except Exception as e:
        print(f"Error during migration: {e}")
    finally:
        if 'connection' in locals() and connection.open:
            connection.close()

if __name__ == "__main__":
    migrate_leads_add_timestamps()