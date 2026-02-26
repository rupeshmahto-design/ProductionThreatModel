"""
Script to manually apply database migrations
"""

from sqlalchemy import create_engine, text, inspect
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Get database URL
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://user:password@localhost/threatmodel")

print("Connecting to database...")
engine = create_engine(DATABASE_URL)

def column_exists(conn, table_name, column_name):
    """Check if a column exists in a table"""
    result = conn.execute(text("""
        SELECT column_name 
        FROM information_schema.columns 
        WHERE table_name=:table_name 
        AND column_name=:column_name
    """), {"table_name": table_name, "column_name": column_name})
    return result.fetchone() is not None

def index_exists(conn, index_name):
    """Check if an index exists"""
    result = conn.execute(text("""
        SELECT indexname 
        FROM pg_indexes 
        WHERE indexname=:index_name
    """), {"index_name": index_name})
    return result.fetchone() is not None

print("\n=== Migration 1: Project Number Column ===")
try:
    with engine.connect() as conn:
        if column_exists(conn, 'threat_assessments', 'project_number'):
            print("✓ Column 'project_number' already exists!")
        else:
            conn.execute(text("""
                ALTER TABLE threat_assessments 
                ADD COLUMN project_number VARCHAR(100)
            """))
            
            conn.execute(text("""
                CREATE INDEX ix_threat_assessments_project_number 
                ON threat_assessments (project_number)
            """))
            
            conn.commit()
            print("✓ Successfully added project_number column and index!")
            
except Exception as e:
    print(f"✗ Error: {e}")

print("\n=== Migration 2: Performance Indexes and Risk Count Cache ===")
try:
    with engine.connect() as conn:
        # Add risk count cache columns
        for col_name in ['critical_count', 'high_count', 'medium_count']:
            if column_exists(conn, 'threat_assessments', col_name):
                print(f"✓ Column '{col_name}' already exists!")
            else:
                conn.execute(text(f"""
                    ALTER TABLE threat_assessments 
                    ADD COLUMN {col_name} INTEGER DEFAULT 0
                """))
                print(f"✓ Added column '{col_name}'")
        
        # Add performance indexes
        indexes = [
            ('ix_threat_assessments_framework', 'framework'),
            ('ix_threat_assessments_risk_type', 'risk_type'),
            ('ix_threat_assessments_status', 'status')
        ]
        
        for idx_name, col_name in indexes:
            if index_exists(conn, idx_name):
                print(f"✓ Index '{idx_name}' already exists!")
            else:
                conn.execute(text(f"""
                    CREATE INDEX {idx_name} 
                    ON threat_assessments ({col_name})
                """))
                print(f"✓ Created index '{idx_name}'")
        
        # Update existing records with computed risk counts
        print("\nUpdating existing records with risk counts...")
        result = conn.execute(text("""
            UPDATE threat_assessments 
            SET 
                critical_count = (LENGTH(UPPER(assessment_report)) - LENGTH(REPLACE(UPPER(assessment_report), 'CRITICAL', ''))) / LENGTH('CRITICAL'),
                high_count = (LENGTH(UPPER(assessment_report)) - LENGTH(REPLACE(UPPER(assessment_report), 'HIGH', ''))) / LENGTH('HIGH'),
                medium_count = (LENGTH(UPPER(assessment_report)) - LENGTH(REPLACE(UPPER(assessment_report), 'MEDIUM', ''))) / LENGTH('MEDIUM')
            WHERE assessment_report IS NOT NULL
            AND (critical_count IS NULL OR critical_count = 0)
        """))
        print(f"✓ Updated {result.rowcount} records with risk counts")
        
        conn.commit()
        print("\n✓ Performance migration completed successfully!")
            
except Exception as e:
    print(f"✗ Error: {e}")
    import traceback
    traceback.print_exc()

print("\n=== All Migrations Complete ===")
print("\nPerformance improvements applied:")
print("  • Added indexes on framework, risk_type, and status columns")
print("  • Added cached risk count columns (critical_count, high_count, medium_count)")
print("  • Computed risk counts for existing assessments")
print("\nYour app should now load much faster!")

