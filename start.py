#!/usr/bin/env python3
"""
Railway startup script with error handling
"""
import os
import sys
from pathlib import Path

def main():
    print("🚀 Starting EnterpriseUI deployment...")
    
    # Check critical environment variables
    print("\n📋 Checking environment variables...")
    required_vars = {
        "DATABASE_URL": os.getenv("DATABASE_URL"),
        "PORT": os.getenv("PORT", "8000")
    }
    
    optional_vars = {
        "ANTHROPIC_API_KEY": os.getenv("ANTHROPIC_API_KEY"),
        "SECRET_KEY": os.getenv("SECRET_KEY"),
        "ENVIRONMENT": os.getenv("ENVIRONMENT", "production")
    }
    
    for key, value in required_vars.items():
        if value:
            print(f"✅ {key}: {'*' * 10} (set)")
        else:
            print(f"❌ {key}: NOT SET")
    
    for key, value in optional_vars.items():
        if value:
            print(f"✅ {key}: {'*' * 10} (set)")
        else:
            print(f"⚠️  {key}: NOT SET (optional but recommended)")
    
    # Check if frontend is built
    print("\n🎨 Checking frontend build...")
    dist_dir = Path(__file__).parent / "dist"
    if dist_dir.exists() and (dist_dir / "index.html").exists():
        print(f"✅ Frontend built at: {dist_dir}")
        assets_dir = dist_dir / "assets"
        if assets_dir.exists():
            asset_count = len(list(assets_dir.glob("*")))
            print(f"   Found {asset_count} asset files")
    else:
        print("⚠️  Frontend not built - will serve API only")
    
    # Check database connection
    print("\n🗄️  Checking database connection...")
    try:
        from database import engine, SessionLocal
        from models import Base
        with engine.connect() as conn:
            print("✅ Database connection successful")
        
        # Create tables if they don't exist
        print("\n📊 Ensuring database tables exist...")
        Base.metadata.create_all(bind=engine)
        print("✅ Database tables ready")
        
        # Create admin user if it doesn't exist
        print("\n👤 Checking for admin user...")
        from models import User, Organization
        from auth import get_password_hash
        db = SessionLocal()
        try:
            admin_exists = db.query(User).filter(User.role == "admin").first()
            if not admin_exists:
                print("   Creating admin user...")
                # Get or create default org
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
                
                # Create admin
                admin_user = User(
                    email="admin@secureai.com",
                    username="admin",
                    password_hash=get_password_hash("admin123"),
                    full_name="Administrator",
                    role="admin",
                    is_active=True,
                    organization_id=default_org.id
                )
                db.add(admin_user)
                db.commit()
                print("✅ Admin user created!")
                print("   Email: admin@secureai.com")
                print("   Password: admin123")
                print("   ⚠️  Change password after first login!")
            else:
                print("✅ Admin user already exists")
        except Exception as e:
            print(f"⚠️  Admin creation error: {e}")
            db.rollback()
        finally:
            db.close()
        
    except Exception as e:
        print(f"❌ Database connection failed: {e}")
        print("   Will attempt to continue anyway...")
    
    # Start the server
    port = int(os.getenv("PORT", "8000"))
    print(f"\n🌐 Starting server on port {port}...")
    print(f"   Environment: {os.getenv('ENVIRONMENT', 'production')}")
    
    os.execvp("uvicorn", [
        "uvicorn",
        "api:app",
        "--host", "0.0.0.0",
        "--port", str(port),
        "--workers", "1",
        "--log-level", "info"
    ])

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"\n💥 Startup failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
