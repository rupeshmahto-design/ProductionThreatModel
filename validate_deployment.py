"""
Pre-deployment validation script
Checks configuration and dependencies before deploying
"""

import os
import sys
from pathlib import Path


def check_environment_file():
    """Check if .env file exists (for local dev)"""
    env_file = Path(".env")
    if env_file.exists():
        print("✅ .env file found (for local development)")
        return True
    else:
        print("ℹ️  No .env file (OK for production - using environment variables)")
        return True


def check_required_files():
    """Check if all required files exist"""
    required_files = [
        "api.py",
        "database.py",
        "models.py",
        "auth.py",
        "requirements.txt",
        "init_db.py",
        "Procfile",
        "render.yaml",
    ]
    
    all_exist = True
    for file in required_files:
        if Path(file).exists():
            print(f"✅ {file}")
        else:
            print(f"❌ {file} - MISSING!")
            all_exist = False
    
    return all_exist


def check_database_url():
    """Check DATABASE_URL format"""
    from database import DATABASE_URL
    
    print(f"\n📊 Database Configuration:")
    print(f"Database URL: {DATABASE_URL[:30]}..." if len(DATABASE_URL) > 30 else f"Database URL: {DATABASE_URL}")
    
    # Check for common issues
    issues = []
    
    if DATABASE_URL.startswith("psql "):
        issues.append("❌ DATABASE_URL starts with 'psql ' - This will be auto-cleaned but should be fixed in env")
    
    if DATABASE_URL.startswith("'") or DATABASE_URL.endswith("'"):
        issues.append("⚠️  DATABASE_URL has quotes - Will be auto-cleaned")
    
    if DATABASE_URL.startswith("postgres://") and not DATABASE_URL.startswith("postgresql://"):
        issues.append("ℹ️  Using postgres:// - Will be auto-converted to postgresql://")
    
    if DATABASE_URL.startswith("sqlite"):
        print("⚠️  Using SQLite (OK for development, use PostgreSQL for production)")
    elif DATABASE_URL.startswith("postgresql://"):
        print("✅ Using PostgreSQL")
        if "sslmode=require" in DATABASE_URL:
            print("✅ SSL mode enabled")
        else:
            issues.append("⚠️  SSL mode not explicitly set - Consider adding ?sslmode=require")
    
    if issues:
        print("\n⚠️  DATABASE_URL Issues detected:")
        for issue in issues:
            print(f"  {issue}")
        print("\n✅ Auto-cleanup is enabled in database.py - These will be handled automatically")
    else:
        print("✅ DATABASE_URL format looks good")
    
    return True


def check_anthropic_key():
    """Check if Anthropic API key is set"""
    api_key = os.getenv("ANTHROPIC_API_KEY", "")
    
    if not api_key:
        print("❌ ANTHROPIC_API_KEY not set!")
        return False
    elif api_key.startswith("sk-ant-"):
        print("✅ ANTHROPIC_API_KEY is set")
        return True
    else:
        print("⚠️  ANTHROPIC_API_KEY is set but doesn't look valid (should start with sk-ant-)")
        return False


def check_secret_key():
    """Check if SECRET_KEY is set"""
    secret_key = os.getenv("SECRET_KEY", "")
    
    if not secret_key:
        print("⚠️  SECRET_KEY not set - Will use default (OK for dev, set for production)")
        return True
    elif len(secret_key) < 32:
        print("⚠️  SECRET_KEY is too short (should be at least 32 characters)")
        return False
    else:
        print("✅ SECRET_KEY is set")
        return True


def check_dependencies():
    """Check if key dependencies can be imported"""
    dependencies = [
        ("fastapi", "FastAPI"),
        ("sqlalchemy", "SQLAlchemy"),
        ("anthropic", "Anthropic AI"),
        ("uvicorn", "Uvicorn"),
        ("pydantic", "Pydantic"),
    ]
    
    all_installed = True
    print("\n📦 Checking Dependencies:")
    
    for module, name in dependencies:
        try:
            __import__(module)
            print(f"✅ {name}")
        except ImportError:
            print(f"❌ {name} - NOT INSTALLED")
            all_installed = False
    
    return all_installed


def test_database_connection():
    """Test database connection"""
    print("\n🔌 Testing Database Connection:")
    try:
        from database import engine
        from sqlalchemy import text
        
        with engine.connect() as conn:
            result = conn.execute(text("SELECT 1"))
            result.fetchone()
            print("✅ Database connection successful")
            return True
    except Exception as e:
        print(f"❌ Database connection failed: {str(e)}")
        return False


def main():
    """Run all validation checks"""
    print("=" * 60)
    print("🚀 PRE-DEPLOYMENT VALIDATION")
    print("=" * 60)
    
    print("\n📁 Checking Required Files:")
    files_ok = check_required_files()
    
    print("\n🔧 Checking Environment:")
    env_ok = check_environment_file()
    
    print("\n🔑 Checking API Keys:")
    anthropic_ok = check_anthropic_key()
    secret_ok = check_secret_key()
    
    print("\n🗄️  Checking Database:")
    db_url_ok = check_database_url()
    
    deps_ok = check_dependencies()
    
    db_conn_ok = test_database_connection()
    
    print("\n" + "=" * 60)
    print("📊 VALIDATION SUMMARY")
    print("=" * 60)
    
    all_checks = [
        ("Required Files", files_ok),
        ("Environment Setup", env_ok),
        ("Anthropic API Key", anthropic_ok),
        ("Secret Key", secret_ok),
        ("Database URL", db_url_ok),
        ("Dependencies", deps_ok),
        ("Database Connection", db_conn_ok),
    ]
    
    passed = sum(1 for _, status in all_checks if status)
    total = len(all_checks)
    
    for check_name, status in all_checks:
        icon = "✅" if status else "❌"
        print(f"{icon} {check_name}")
    
    print("\n" + "=" * 60)
    if passed == total:
        print("🎉 ALL CHECKS PASSED! Ready for deployment.")
        print("=" * 60)
        return 0
    else:
        print(f"⚠️  {total - passed} CHECK(S) FAILED")
        print("Please fix the issues above before deploying.")
        print("=" * 60)
        return 1


if __name__ == "__main__":
    sys.exit(main())
