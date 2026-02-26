"""
Create Admin User for SecureAI
Run: python create_admin.py
"""
import os
import asyncio
from database import SessionLocal
from models import User, Organization
from auth import get_password_hash

async def create_admin():
    db = SessionLocal()
    try:
        admin_email = os.getenv("ADMIN_EMAIL", "admin@secureai.com")
        admin_password = os.getenv("ADMIN_PASSWORD", "admin123")
        
        # Check if admin exists
        existing_admin = db.query(User).filter(User.email == admin_email).first()
        if existing_admin:
            print(f"❌ Admin user with email {admin_email} already exists!")
            return
        
        # Create or get default organization
        default_org = db.query(Organization).filter(Organization.slug == "default").first()
        if not default_org:
            default_org = Organization(
                name="SecureAI Organization",
                slug="default",
                max_users=1000,
                max_api_calls_per_month=100000
            )
            db.add(default_org)
            db.commit()
            db.refresh(default_org)
        
        # Create admin user
        admin_user = User(
            email=admin_email,
            username="admin",
            password_hash=get_password_hash(admin_password),
            full_name="SecureAI Administrator",
            role="admin",
            is_active=True,
            organization_id=default_org.id
        )
        db.add(admin_user)
        db.commit()
        
        print("✅ Admin user created successfully!")
        print("")
        print("=" * 50)
        print("ADMIN CREDENTIALS")
        print("=" * 50)
        print(f"Email:    {admin_email}")
        print(f"Password: {admin_password}")
        print("=" * 50)
        print("")
        print("⚠️  IMPORTANT: Change this password after first login!")
        print("")
        print("Role: admin")
    except Exception as e:
        print(f"❌ Error creating admin: {e}")
        import traceback
        traceback.print_exc()
        db.rollback()
    finally:
        db.close()

if __name__ == "__main__":
    asyncio.run(create_admin())
