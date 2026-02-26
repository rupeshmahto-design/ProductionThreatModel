"""
Database initialization and seeding script
Creates initial organization and admin user
"""

import os
import sys
from sqlalchemy.orm import Session
from sqlalchemy import text
from datetime import datetime

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from database import SessionLocal, init_db, engine
from models import Organization, User, APIKey, Base
from auth import PasswordAuth


def apply_migration_if_needed():
    """Apply project_number column migration if it doesn't exist"""
    db = SessionLocal()
    try:
        # Check if project_number column exists
        result = db.execute(text("""
            SELECT column_name 
            FROM information_schema.columns 
            WHERE table_name='threat_assessments' 
            AND column_name='project_number'
        """))
        
        if result.fetchone():
            print("✅ Migration already applied (project_number exists)")
        else:
            print("🔄 Applying migration: Adding project_number column...")
            # Add the column
            db.execute(text("""
                ALTER TABLE threat_assessments 
                ADD COLUMN project_number VARCHAR(100)
            """))
            
            # Create index
            db.execute(text("""
                CREATE INDEX ix_threat_assessments_project_number 
                ON threat_assessments (project_number)
            """))
            
            db.commit()
            print("✅ Migration applied successfully!")
    except Exception as e:
        print(f"⚠️ Migration note: {e}")
        db.rollback()
    finally:
        db.close()


def create_tables():
    """Create all database tables"""
    print("Creating database tables...")
    Base.metadata.create_all(bind=engine)
    print("✅ Tables created successfully!")
    
    # Apply missing columns migration if needed
    apply_migration_if_needed()


def seed_initial_data():
    """Seed initial organization and admin user"""
    db = SessionLocal()
    
    try:
        # Check if data already exists
        existing_org = db.query(Organization).first()
        if existing_org:
            print("⚠️  Database already seeded. Skipping...")
            return
        
        print("\n🌱 Seeding initial data...")
        
        # Create default organization
        org = Organization(
            name="Default Organization",
            slug="default",
            domain="example.com",
            saml_enabled=False,
            max_users=50,
            max_api_calls_per_month=10000,
            storage_limit_gb=100.0
        )
        db.add(org)
        db.flush()  # Get the org ID
        
        print(f"✅ Created organization: {org.name} (ID: {org.id})")
        
        # Create admin user
        admin_user = User(
            email="admin@example.com",
            username="admin",
            full_name="System Administrator",
            password_hash=PasswordAuth.hash_password("admin123"),  # Change this!
            role="super_admin",
            is_org_admin=True,
            organization_id=org.id,
            is_active=True
        )
        db.add(admin_user)
        db.flush()
        
        print(f"✅ Created admin user: {admin_user.email}")
        print(f"   Default password: admin123 (⚠️  CHANGE THIS!)")
        
        # Create default API key for admin
        api_key_value = APIKey.generate_key()
        api_key = APIKey(
            name="Admin Default Key",
            key_prefix=api_key_value[:12],
            key_hash=APIKey.hash_key(api_key_value),
            scopes=[
                "threat_modeling:read",
                "threat_modeling:write",
                "admin:users",
                "admin:audit",
                "admin:stats"
            ],
            organization_id=org.id,
            user_id=admin_user.id,
            is_active=True
        )
        db.add(api_key)
        
        db.commit()
        
        print(f"✅ Created API key: {api_key.name}")
        print(f"\n🔑 API Key: {api_key_value}")
        print(f"   ⚠️  Save this key! You won't see it again.\n")
        
        print("\n✅ Initial data seeded successfully!")
        print("\n📝 Summary:")
        print(f"   Organization: {org.name}")
        print(f"   Admin Email: {admin_user.email}")
        print(f"   Admin Password: admin123")
        print(f"   API Key: {api_key_value}")
        print("\n⚠️  Remember to change the default password!")
        
    except Exception as e:
        db.rollback()
        print(f"❌ Error seeding data: {str(e)}")
        raise
    finally:
        db.close()


def create_sample_data():
    """Create sample threat assessments for testing"""
    db = SessionLocal()
    
    try:
        from models import ThreatAssessment, AuditLog
        
        print("\n🎯 Creating sample data...")
        
        # Get the first organization and user
        org = db.query(Organization).first()
        user = db.query(User).first()
        
        if not org or not user:
            print("❌ No organization or user found. Run seed_initial_data first.")
            return
        
        # Create sample threat assessments
        sample_assessments = [
            {
                "project_name": "Web Application Security Assessment",
                "framework": "STRIDE",
                "risk_type": "Application Security",
                "system_description": "E-commerce web application with user authentication",
                "assessment_report": "Sample threat modeling report for web application..."
            },
            {
                "project_name": "Cloud Infrastructure Review",
                "framework": "MITRE ATT&CK",
                "risk_type": "Infrastructure Risk",
                "system_description": "AWS-based microservices architecture",
                "assessment_report": "Sample threat modeling report for cloud infrastructure..."
            },
            {
                "project_name": "AI Model Security",
                "framework": "VAST",
                "risk_type": "Model Risk",
                "system_description": "Machine learning model for fraud detection",
                "assessment_report": "Sample threat modeling report for AI/ML systems..."
            }
        ]
        
        for data in sample_assessments:
            assessment = ThreatAssessment(
                organization_id=org.id,
                user_id=user.id,
                project_name=data["project_name"],
                framework=data["framework"],
                risk_type=data["risk_type"],
                system_description=data["system_description"],
                assessment_report=data["assessment_report"],
                status="completed",
                report_metadata={"sample": True}
            )
            db.add(assessment)
            print(f"   ✅ Created sample assessment: {data['project_name']}")
        
        db.commit()
        print("\n✅ Sample data created successfully!")
        
    except Exception as e:
        db.rollback()
        print(f"❌ Error creating sample data: {str(e)}")
        raise
    finally:
        db.close()


def reset_database():
    """Reset the entire database (⚠️  USE WITH CAUTION!)"""
    print("\n⚠️  WARNING: This will DELETE ALL DATA!")
    response = input("Are you sure you want to reset the database? (yes/no): ")
    
    if response.lower() == 'yes':
        print("\n🔄 Resetting database...")
        Base.metadata.drop_all(bind=engine)
        print("✅ Database reset complete!")
        create_tables()
        seed_initial_data()
    else:
        print("❌ Database reset cancelled")


def main():
    """Main initialization function"""
    print("=" * 60)
    print("🔧 Database Initialization Script")
    print("=" * 60)
    
    import argparse
    parser = argparse.ArgumentParser(description="Initialize database for Threat Modeling Tool")
    parser.add_argument('--create-tables', action='store_true', help='Create database tables')
    parser.add_argument('--seed', action='store_true', help='Seed initial data')
    parser.add_argument('--sample-data', action='store_true', help='Create sample data')
    parser.add_argument('--reset', action='store_true', help='Reset database (⚠️  DELETES ALL DATA)')
    parser.add_argument('--all', action='store_true', help='Create tables and seed data')
    
    args = parser.parse_args()
    
    # Check database connection
    try:
        print("\n🔍 Checking database connection...")
        db = SessionLocal()
        db.execute(text("SELECT 1"))
        db.close()
        print("✅ Database connection successful!")
    except Exception as e:
        print(f"❌ Database connection failed: {str(e)}")
        print("\nMake sure:")
        print("  1. PostgreSQL is running")
        print("  2. DATABASE_URL environment variable is set correctly")
        print(f"  3. Current DATABASE_URL: {os.getenv('DATABASE_URL', 'Not set')}")
        sys.exit(1)
    
    if args.reset:
        reset_database()
    elif args.all:
        create_tables()
        seed_initial_data()
    else:
        if args.create_tables:
            create_tables()
        if args.seed:
            seed_initial_data()
        if args.sample_data:
            create_sample_data()
        
        if not (args.create_tables or args.seed or args.sample_data):
            print("\nNo action specified. Available options:")
            print("  --create-tables    Create database tables")
            print("  --seed            Seed initial data")
            print("  --sample-data     Create sample data")
            print("  --all             Create tables and seed data")
            print("  --reset           Reset database (⚠️  DELETES ALL DATA)")
            print("\nExample: python init_db.py --all")


if __name__ == "__main__":
    main()
