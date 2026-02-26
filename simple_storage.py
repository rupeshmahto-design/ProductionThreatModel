"""
Simple JSON-based storage for users and assessments
No database required!
"""

import json
import os
from datetime import datetime
from pathlib import Path
import hashlib

STORAGE_DIR = Path("data")
USERS_FILE = STORAGE_DIR / "users.json"
ASSESSMENTS_FILE = STORAGE_DIR / "assessments.json"

# Ensure storage directory exists
STORAGE_DIR.mkdir(exist_ok=True)


def _load_json(filepath):
    """Load JSON file or return empty dict"""
    if filepath.exists():
        with open(filepath, 'r', encoding='utf-8') as f:
            return json.load(f)
    return {}


def _save_json(filepath, data):
    """Save data to JSON file"""
    with open(filepath, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2, default=str)


def hash_password(password):
    """Simple password hashing"""
    return hashlib.sha256(password.encode()).hexdigest()


# ============= USER MANAGEMENT =============

def create_user(username, password, email, is_admin=False):
    """Create a new user"""
    users = _load_json(USERS_FILE)
    
    if username in users:
        return False, "Username already exists"
    
    users[username] = {
        "password_hash": hash_password(password),
        "email": email,
        "is_admin": is_admin,
        "created_at": datetime.now().isoformat()
    }
    
    _save_json(USERS_FILE, users)
    return True, "User created successfully"


def authenticate_user(username, password):
    """Authenticate a user"""
    users = _load_json(USERS_FILE)
    
    if username not in users:
        return None
    
    user = users[username]
    if user["password_hash"] == hash_password(password):
        return {
            "username": username,
            "email": user["email"],
            "is_admin": user["is_admin"]
        }
    return None


def get_all_users():
    """Get all users (admin only)"""
    users = _load_json(USERS_FILE)
    return [
        {
            "username": username,
            "email": data["email"],
            "is_admin": data["is_admin"],
            "created_at": data["created_at"]
        }
        for username, data in users.items()
    ]


def initialize_default_users():
    """Create default admin and demo user if none exist"""
    users = _load_json(USERS_FILE)
    
    if not users:
        # Create admin
        users["admin"] = {
            "password_hash": hash_password("admin123"),
            "email": "admin@example.com",
            "is_admin": True,
            "created_at": datetime.now().isoformat()
        }
        
        # Create demo user
        users["demo"] = {
            "password_hash": hash_password("demo123"),
            "email": "demo@example.com",
            "is_admin": False,
            "created_at": datetime.now().isoformat()
        }
        
        _save_json(USERS_FILE, users)
        return True
    return False


# ============= ASSESSMENT MANAGEMENT =============

def save_assessment(username, assessment_data):
    """Save an assessment for a user"""
    assessments = _load_json(ASSESSMENTS_FILE)
    
    if username not in assessments:
        assessments[username] = []
    
    # Add metadata
    assessment_data["id"] = len(assessments[username]) + 1
    assessment_data["created_at"] = datetime.now().isoformat()
    assessment_data["username"] = username
    
    assessments[username].append(assessment_data)
    _save_json(ASSESSMENTS_FILE, assessments)
    
    return assessment_data["id"]


def get_user_assessments(username):
    """Get all assessments for a user"""
    assessments = _load_json(ASSESSMENTS_FILE)
    return assessments.get(username, [])


def get_all_assessments():
    """Get all assessments from all users (admin only)"""
    assessments = _load_json(ASSESSMENTS_FILE)
    all_assessments = []
    
    for username, user_assessments in assessments.items():
        all_assessments.extend(user_assessments)
    
    # Sort by created_at descending
    all_assessments.sort(key=lambda x: x.get("created_at", ""), reverse=True)
    return all_assessments


def delete_assessment(username, assessment_id):
    """Delete an assessment"""
    assessments = _load_json(ASSESSMENTS_FILE)
    
    if username in assessments:
        assessments[username] = [
            a for a in assessments[username] 
            if a["id"] != assessment_id
        ]
        _save_json(ASSESSMENTS_FILE, assessments)
        return True
    return False


def get_assessment_stats():
    """Get assessment statistics"""
    assessments = _load_json(ASSESSMENTS_FILE)
    
    total_assessments = sum(len(user_assessments) for user_assessments in assessments.values())
    total_users = len(assessments)
    
    frameworks = {}
    risk_areas = {}
    
    for user_assessments in assessments.values():
        for assessment in user_assessments:
            framework = assessment.get("framework", "Unknown")
            frameworks[framework] = frameworks.get(framework, 0) + 1
            
            risk_area = assessment.get("risk_area", "Unknown")
            risk_areas[risk_area] = risk_areas.get(risk_area, 0) + 1
    
    return {
        "total_assessments": total_assessments,
        "total_users": total_users,
        "frameworks": frameworks,
        "risk_areas": risk_areas
    }


# Initialize default users on import
initialize_default_users()
