"""
AI-Powered Threat Modeling Tool
Enterprise-grade threat assessment with PostgreSQL backend
"""

import os
import io
import base64
from typing import List
from datetime import datetime
from pathlib import Path
import json
from zoneinfo import ZoneInfo

import anthropic
import streamlit as st
from sqlalchemy.orm import Session

import admin_dashboard
from auth import PasswordAuth
from database import SessionLocal, init_db, engine
from models import ThreatAssessment, User, Organization

# Apply migrations before any database operations
def apply_migrations():
    """Apply all pending migrations if they don't exist"""
    from sqlalchemy import text
    db = SessionLocal()
    try:
        # Migration 1: project_number column
        result = db.execute(text("""
            SELECT column_name 
            FROM information_schema.columns 
            WHERE table_name='threat_assessments' 
            AND column_name='project_number'
        """))
        
        if not result.fetchone():
            print("🔄 Applying migration: Adding project_number column...")
            db.execute(text("ALTER TABLE threat_assessments ADD COLUMN project_number VARCHAR(100)"))
            db.execute(text("CREATE INDEX IF NOT EXISTS ix_threat_assessments_project_number ON threat_assessments (project_number)"))
            db.commit()
            print("✅ project_number migration applied!")
        
        # Migration 2: Performance indexes and risk count cache
        result = db.execute(text("""
            SELECT column_name 
            FROM information_schema.columns 
            WHERE table_name='threat_assessments' 
            AND column_name='critical_count'
        """))
        
        if not result.fetchone():
            print("🔄 Applying performance optimization migration...")
            
            # Add risk count columns
            db.execute(text("ALTER TABLE threat_assessments ADD COLUMN critical_count INTEGER DEFAULT 0"))
            db.execute(text("ALTER TABLE threat_assessments ADD COLUMN high_count INTEGER DEFAULT 0"))
            db.execute(text("ALTER TABLE threat_assessments ADD COLUMN medium_count INTEGER DEFAULT 0"))
            
            # Add indexes for frequently filtered columns
            db.execute(text("CREATE INDEX IF NOT EXISTS ix_threat_assessments_framework ON threat_assessments (framework)"))
            db.execute(text("CREATE INDEX IF NOT EXISTS ix_threat_assessments_risk_type ON threat_assessments (risk_type)"))
            db.execute(text("CREATE INDEX IF NOT EXISTS ix_threat_assessments_status ON threat_assessments (status)"))
            
            # Update existing records with risk counts
            db.execute(text("""
                UPDATE threat_assessments 
                SET 
                    critical_count = (LENGTH(UPPER(assessment_report)) - LENGTH(REPLACE(UPPER(assessment_report), 'CRITICAL', ''))) / LENGTH('CRITICAL'),
                    high_count = (LENGTH(UPPER(assessment_report)) - LENGTH(REPLACE(UPPER(assessment_report), 'HIGH', ''))) / LENGTH('HIGH'),
                    medium_count = (LENGTH(UPPER(assessment_report)) - LENGTH(REPLACE(UPPER(assessment_report), 'MEDIUM', ''))) / LENGTH('MEDIUM')
                WHERE assessment_report IS NOT NULL
            """))
            
            db.commit()
            print("✅ Performance optimization migration applied!")
        else:
            print("✅ All migrations already applied")
            
    except Exception as e:
        print(f"⚠️ Migration error: {e}")
        db.rollback()
    finally:
        db.close()

# Initialize database tables and seed data on startup
try:
    init_db()
    apply_migrations()
    
    # Seed initial admin user if database is empty
    db = SessionLocal()
    try:
        if db.query(Organization).count() == 0:
            from models import Organization
            org = Organization(
                name="Default Organization",
                slug="default",
                domain="example.com",
                saml_enabled=False,
                max_users=50
            )
            db.add(org)
            db.commit()
            db.refresh(org)
            
            # Create admin user
            admin = User(
                email="admin@example.com",
                username="admin",
                full_name="System Administrator",
                password_hash=PasswordAuth.hash_password("admin123"),
                role="super_admin",
                is_active=True,
                is_org_admin=True,
                organization_id=org.id
            )
            db.add(admin)
            db.commit()
            print("✅ Database initialized with default admin user")
    finally:
        db.close()
except Exception as e:
    print(f"Database initialization: {e}")

# Page configuration
st.set_page_config(
    page_title="AI Threat Modeling Tool",
    page_icon="🔒",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Initialize sidebar pin state
if "sidebar_pinned" not in st.session_state:
    st.session_state.sidebar_pinned = True
if "sidebar_hovered" not in st.session_state:
    st.session_state.sidebar_hovered = False

# Custom CSS for enterprise-grade professional UI
st.markdown("""
    <style>
    /* Enterprise Color Palette */
    :root {
        --primary-dark: #0d1b2a;
        --primary: #1a2f4a;
        --primary-light: #2a4a6e;
        --accent-primary: #0891b2;
        --accent-secondary: #06b6d4;
        --accent-tertiary: #14b8a6;
        --success: #059669;
        --warning: #d97706;
        --danger: #dc2626;
        --neutral-50: #f9fafb;
        --neutral-100: #f3f4f6;
        --neutral-200: #e5e7eb;
        --neutral-300: #d1d5db;
        --neutral-600: #4b5563;
        --neutral-900: #111827;
    }
    
    /* Global Styles - Enterprise Professional Design */
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&display=swap');
    
    * {
        font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Roboto', sans-serif;
        letter-spacing: -0.01em;
    }
    
    /* Main Layout - Sophisticated Background */
    .main {
        background: linear-gradient(135deg, #f9fafb 0%, #f3f4f6 50%, #eff2f5 100%);
        padding: 2.5rem 3rem;
    }
    
    .block-container {
        max-width: 1400px;
        padding: 2rem 1rem;
    }
    
    /* Sidebar Optimization */
    [data-testid="stSidebar"] {
        padding: 1rem 0.75rem !important;
    }
    
    [data-testid="stSidebar"] h3 {
        margin-top: 0 !important;
        margin-bottom: 0.5rem !important;
        font-size: 1.1rem !important;
    }
    
    [data-testid="stSidebar"] p {
        margin: 0 !important;
    }
    
    [data-testid="stSidebar"] hr {
        margin: 1rem 0 !important;
        padding: 0 !important;
    }
    
    [data-testid="stSidebar"] .stButton>button {
        font-size: 0.875rem !important;
        padding: 0.5rem 1rem !important;
        height: auto !important;
    }
    
    /* Typography - Enterprise Hierarchy */
    h1 {
        color: var(--primary-dark) !important;
        font-weight: 800 !important;
        font-size: 2.75rem !important;
        margin-bottom: 0.75rem !important;
        letter-spacing: -0.02em !important;
    }
    
    h2 {
        color: var(--primary-dark) !important;
        font-weight: 700 !important;
        font-size: 1.875rem !important;
        margin-top: 2.5rem !important;
        margin-bottom: 1.75rem !important;
        padding-bottom: 1rem !important;
        border-bottom: 3px solid var(--accent-primary) !important;
    }
    
    h3 {
        color: var(--primary) !important;
        font-weight: 700 !important;
        font-size: 1.375rem !important;
        margin-top: 1.5rem !important;
        margin-bottom: 1rem !important;
    }
    
    h4 {
        color: var(--primary) !important;
        font-weight: 600 !important;
        font-size: 1.125rem !important;
    }
    
    p {
        color: var(--neutral-600);
        line-height: 1.7;
        font-weight: 400;
    }
    
    /* Professional Sidebar */
    [data-testid="stSidebar"] {
        background: linear-gradient(180deg, #ffffff 0%, #f8fafb 100%);
        border-right: 1px solid var(--neutral-200);
        box-shadow: 4px 0 20px rgba(13, 27, 42, 0.08);
    }
    
    [data-testid="stSidebar"] .element-container {
        padding: 0.75rem 1.25rem;
    }
    
    /* Pin Button Styling */
    [data-testid="stSidebar"] button[key="pin_toggle"] {
        background: linear-gradient(135deg, var(--accent-primary) 0%, var(--accent-secondary) 100%) !important;
        color: white !important;
        border-radius: 10px !important;
        font-weight: 700 !important;
        border: none !important;
        padding: 0.75rem 0.875rem !important;
        font-size: 1.1rem !important;
        box-shadow: 0 4px 12px rgba(8, 145, 178, 0.2) !important;
        transition: all 0.3s ease !important;
    }
    
    [data-testid="stSidebar"] button[key="pin_toggle"]:hover {
        background: linear-gradient(135deg, var(--accent-secondary) 0%, #14b8a6 100%) !important;
        box-shadow: 0 6px 16px rgba(8, 145, 178, 0.3) !important;
        transform: translateY(-2px) !important;
    }
    
    /* Enterprise Buttons - Premium Styling */
    .stButton>button {
        background: linear-gradient(135deg, var(--primary) 0%, var(--primary-light) 100%) !important;
        color: white !important;
        border-radius: 12px !important;
        font-weight: 600 !important;
        border: none !important;
        padding: 0.875rem 1.75rem !important;
        font-size: 0.975rem !important;
        letter-spacing: -0.005em !important;
        box-shadow: 0 6px 20px rgba(13, 27, 42, 0.15) !important;
        transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1) !important;
        position: relative;
        overflow: hidden;
    }
    
    .stButton>button::before {
        content: "";
        position: absolute;
        top: 0;
        left: -100%;
        width: 100%;
        height: 100%;
        background: rgba(255, 255, 255, 0.2);
        transition: left 0.3s ease;
    }
    
    .stButton>button:hover {
        background: linear-gradient(135deg, #163a52 0%, var(--primary) 100%) !important;
        box-shadow: 0 10px 30px rgba(8, 145, 178, 0.25) !important;
        transform: translateY(-2px) !important;
    }
    
    .stButton>button:hover::before {
        left: 100%;
    }
    
    .stButton>button:active {
        transform: translateY(0) !important;
    }
    
    /* Secondary Buttons */
    .stButton>button[kind="secondary"] {
        background: white !important;
        color: var(--primary) !important;
        border: 2px solid var(--accent-primary) !important;
        box-shadow: 0 3px 10px rgba(13, 27, 42, 0.05) !important;
    }
    
    .stButton>button[kind="secondary"]:hover {
        background: var(--neutral-50) !important;
        border-color: var(--primary-light) !important;
    }
    
    /* Professional Input Fields */
    .stTextInput>div>div>input,
    .stNumberInput>div>div>input {
        border: 1.75px solid #dbe3ed !important;
        border-radius: 12px !important;
        padding: 0.9rem 1.1rem !important;
        font-size: 0.975rem !important;
        background: linear-gradient(180deg, #f8fafc 0%, #f3f6fb 100%) !important;
        transition: all 0.25s ease !important;
        box-shadow: 0 2px 8px rgba(13, 27, 42, 0.05) !important;
        color: var(--neutral-900) !important;
        height: 52px !important;
    }

    .stTextInput>div>div>input::placeholder {
        color: #94a3b8 !important;
    }

    .stSelectbox>div>div,
    .stMultiSelect>div>div {
        border: 1.75px solid #dbe3ed !important;
        border-radius: 12px !important;
        background: linear-gradient(180deg, #f8fafc 0%, #f3f6fb 100%) !important;
        box-shadow: 0 2px 8px rgba(13, 27, 42, 0.05) !important;
        transition: all 0.25s ease !important;
        padding: 0.35rem 0.65rem !important;
        min-height: 52px !important;
    }

    .stSelectbox>div>div:focus-within,
    .stMultiSelect>div>div:focus-within {
        border-color: var(--accent-primary) !important;
        box-shadow: 0 0 0 4px rgba(8, 145, 178, 0.1) !important;
        outline: none !important;
    }

    .stSelectbox>div>div>div,
    .stMultiSelect>div>div>div {
        padding-left: 0.35rem !important;
    }

    .stTextArea>div>div>textarea {
        border: 1.75px solid #dbe3ed !important;
        border-radius: 12px !important;
        padding: 1rem 1.1rem !important;
        font-size: 0.975rem !important;
        background: linear-gradient(180deg, #f8fafc 0%, #f3f6fb 100%) !important;
        transition: all 0.25s ease !important;
        box-shadow: 0 2px 8px rgba(13, 27, 42, 0.05) !important;
        color: var(--neutral-900) !important;
        min-height: 120px !important;
    }
    
    .stTextInput>div>div>input:focus,
    .stTextArea>div>div>textarea:focus {
        border-color: var(--accent-primary) !important;
        box-shadow: 0 0 0 4px rgba(8, 145, 178, 0.1) !important;
        outline: none !important;
    }

    /* Input labels */
    .stSelectbox label,
    .stMultiSelect label,
    .stTextInput label,
    .stNumberInput label {
        color: #1f2937 !important;
        font-weight: 700 !important;
        font-size: 0.95rem !important;
    }
    
    /* Premium Cards */
    .framework-card {
        background: white !important;
        border: 2px solid var(--neutral-200) !important;
        padding: 2rem !important;
        border-radius: 16px !important;
        margin: 1rem 0 !important;
        transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1) !important;
        box-shadow: 0 4px 12px rgba(13, 27, 42, 0.06) !important;
        position: relative;
        overflow: hidden;
    }
    
    .framework-card::before {
        content: "";
        position: absolute;
        top: 0;
        left: 0;
        width: 100%;
        height: 5px;
        background: linear-gradient(90deg, var(--accent-primary), var(--accent-secondary));
        opacity: 0;
        transition: opacity 0.3s ease;
    }
    
    .framework-card:hover {
        border-color: var(--accent-primary) !important;
        box-shadow: 0 12px 32px rgba(8, 145, 178, 0.12) !important;
        transform: translateY(-4px) !important;
    }
    
    .framework-card:hover::before {
        opacity: 1;
    }
    
    .framework-card.selected {
        background: linear-gradient(135deg, #f0f9fb 0%, #ecf8fb 100%) !important;
        border-color: var(--accent-primary) !important;
        box-shadow: 0 12px 32px rgba(8, 145, 178, 0.15) !important;
        border-left: 5px solid var(--accent-primary) !important;
    }
    
    .framework-card.disabled {
        background: #f9fafb !important;
        border: 2px dashed #d1d5db !important;
        opacity: 0.7 !important;
        cursor: not-allowed !important;
        position: relative;
    }
    
    .framework-card.disabled:hover {
        transform: none !important;
        box-shadow: 0 4px 12px rgba(13, 27, 42, 0.06) !important;
    }
    
    .coming-soon-badge {
        display: inline-block;
        background: linear-gradient(135deg, #fbbf24 0%, #f59e0b 100%);
        color: white;
        padding: 4px 12px;
        border-radius: 12px;
        font-size: 0.75rem;
        font-weight: 600;
        margin-left: 8px;
        text-transform: uppercase;
        letter-spacing: 0.5px;
    }
    
    .activation-note {
        color: #6b7280;
        font-size: 0.85rem;
        font-style: italic;
        margin-top: 8px;
        padding: 8px;
        background: #fef3c7;
        border-radius: 6px;
        border-left: 3px solid #f59e0b;
    }
    
    /* Risk Cards */
    .risk-card {
        background: white !important;
        border: 2px solid var(--neutral-200) !important;
        padding: 1.75rem !important;
        border-radius: 14px !important;
        margin: 0.75rem 0 !important;
        transition: all 0.25s ease !important;
        box-shadow: 0 2px 8px rgba(13, 27, 42, 0.04) !important;
    }
    
    .risk-card:hover {
        border-color: var(--accent-secondary) !important;
        box-shadow: 0 8px 20px rgba(8, 145, 178, 0.08) !important;
        transform: translateY(-2px) !important;
    }
    
    /* Professional File Upload */
    .upload-box {
        border: 3px dashed var(--accent-primary) !important;
        border-radius: 16px !important;
        padding: 3.5rem 2rem !important;
        text-align: center !important;
        background: linear-gradient(135deg, #f0f9fb 0%, #ecf8fb 100%) !important;
        margin: 2rem 0 !important;
        transition: all 0.3s ease !important;
    }
    
    .upload-box:hover {
        border-color: var(--accent-secondary) !important;
        background: linear-gradient(135deg, #e0f2fe 0%, #cffafe 100%) !important;
        transform: scale(1.01) !important;
    }
    
    [data-testid="stFileUploader"] {
        background: white;
        border: 2px solid var(--neutral-200);
        border-radius: 14px;
        padding: 1.75rem;
        box-shadow: 0 2px 8px rgba(13, 27, 42, 0.05);
    }
    
    /* Enterprise Hero Banner */
    .hero-banner {
        background: linear-gradient(135deg, var(--primary-dark) 0%, var(--primary) 40%, var(--primary-light) 100%);
        padding: 4rem 3rem;
        border-radius: 24px;
        margin-bottom: 3rem;
        box-shadow: 0 20px 50px rgba(13, 27, 42, 0.3), inset 0 1px 0 rgba(255, 255, 255, 0.2);
        position: relative;
        overflow: hidden;
    }
    
    .hero-banner::before {
        content: "";
        position: absolute;
        top: -50%;
        right: -10%;
        width: 500px;
        height: 500px;
        background: radial-gradient(circle, rgba(8, 145, 178, 0.15) 0%, transparent 70%);
        border-radius: 50%;
    }
    
    .hero-banner::after {
        content: "";
        position: absolute;
        bottom: -30%;
        left: -5%;
        width: 400px;
        height: 400px;
        background: radial-gradient(circle, rgba(20, 184, 166, 0.1) 0%, transparent 70%);
        border-radius: 50%;
    }
    
    .hero-banner h1 {
        color: white !important;
        font-size: 3.25rem !important;
        font-weight: 800 !important;
        margin-bottom: 1rem !important;
        text-shadow: 0 4px 16px rgba(0, 0, 0, 0.2);
        background: none !important;
        -webkit-text-fill-color: white !important;
        position: relative;
        z-index: 2;
    }
    
    .hero-banner p {
        color: rgba(255, 255, 255, 0.95) !important;
        font-size: 1.35rem !important;
        font-weight: 500 !important;
        margin: 0 !important;
        position: relative;
        z-index: 2;
    }
    
    /* Modern Tabs */
    .stTabs [data-baseweb="tab-list"] {
        gap: 0.5rem;
        background: white;
        padding: 1.25rem;
        border-radius: 14px;
        box-shadow: 0 3px 12px rgba(13, 27, 42, 0.06);
        border: 1px solid var(--neutral-200);
    }
    
    .stTabs [data-baseweb="tab"] {
        height: 3.75rem;
        padding: 0 2.25rem;
        background: transparent;
        border-radius: 10px;
        color: var(--neutral-600);
        font-weight: 600;
        font-size: 1.05rem;
        border: none;
        transition: all 0.25s ease;
        box-shadow: none !important;
    }
    
    .stTabs [data-baseweb="tab"]:hover {
        background: var(--neutral-100);
        color: var(--primary);
    }
    
    .stTabs [data-baseweb="tab"][aria-selected="true"] {
        background: linear-gradient(135deg, var(--accent-primary) 0%, var(--accent-secondary) 100%);
        color: white;
        box-shadow: 0 6px 20px rgba(8, 145, 178, 0.25) !important;
    }
    
    /* Professional Tables */
    .dataframe {
        border: none !important;
        border-radius: 14px !important;
        overflow: hidden !important;
        box-shadow: 0 3px 12px rgba(13, 27, 42, 0.06) !important;
    }
    
    .dataframe th {
        background: linear-gradient(135deg, var(--primary-dark) 0%, var(--primary) 100%) !important;
        color: white !important;
        font-weight: 700 !important;
        padding: 1.25rem !important;
        text-align: left !important;
        border: none !important;
        font-size: 0.95rem !important;
    }
    
    .dataframe td {
        padding: 1rem 1.25rem !important;
        border-bottom: 1px solid var(--neutral-200) !important;
        color: var(--neutral-900) !important;
        font-size: 0.95rem !important;
    }
    
    .dataframe tr:hover {
        background: var(--neutral-50) !important;
    }
    
    /* Enterprise Metrics */
    [data-testid="stMetricValue"] {
        font-size: 2.5rem !important;
        font-weight: 800 !important;
        color: var(--primary-dark) !important;
    }
    
    [data-testid="stMetricLabel"] {
        font-size: 0.875rem !important;
        font-weight: 700 !important;
        color: var(--neutral-600) !important;
        text-transform: uppercase !important;
        letter-spacing: 0.1em !important;
    }
    
    /* Professional Messages */
    .stSuccess, .stInfo, .stWarning, .stError {
        border-radius: 14px !important;
        border-left: 5px solid !important;
        padding: 1.25rem 1.75rem !important;
        font-weight: 500 !important;
        font-size: 0.975rem !important;
    }
    
    .stSuccess {
        border-left-color: var(--success) !important;
        background-color: rgba(5, 150, 105, 0.05) !important;
        color: #047857 !important;
    }
    
    .stInfo {
        border-left-color: var(--accent-primary) !important;
        background-color: rgba(8, 145, 178, 0.05) !important;
        color: var(--accent-primary) !important;
    }
    
    .stWarning {
        border-left-color: var(--warning) !important;
        background-color: rgba(217, 119, 6, 0.05) !important;
        color: #b45309 !important;
    }
    
    .stError {
        border-left-color: var(--danger) !important;
        background-color: rgba(220, 38, 38, 0.05) !important;
        color: #991b1b !important;
    }
    
    /* Expanders - Enterprise Style */
    .streamlit-expanderHeader {
        background: white !important;
        border: 2px solid var(--neutral-200) !important;
        border-radius: 12px !important;
        padding: 1.25rem 1.75rem !important;
        font-weight: 600 !important;
        color: var(--primary-dark) !important;
        transition: all 0.2s ease !important;
    }
    
    .streamlit-expanderHeader:hover {
        background: var(--neutral-50) !important;
        border-color: var(--accent-primary) !important;
        color: var(--accent-primary) !important;
    }
    
    /* Checkboxes */
    .stCheckbox {
        padding: 0.75rem 0;
    }
    
    .stCheckbox > label {
        font-weight: 600 !important;
        color: var(--primary) !important;
        font-size: 1rem !important;
    }
    
    /* Professional Dividers */
    hr {
        margin: 2.5rem 0 !important;
        border: none !important;
        border-top: 2px solid var(--neutral-200) !important;
    }
    
    /* Configuration Section */
    .config-section {
        background: white;
        padding: 2rem;
        border-radius: 14px;
        border: 2px solid var(--neutral-200);
        margin: 1.5rem 0;
        box-shadow: 0 3px 12px rgba(13, 27, 42, 0.05);
        transition: all 0.2s ease;
    }
    
    .config-section:hover {
        border-color: var(--accent-primary);
        box-shadow: 0 6px 20px rgba(8, 145, 178, 0.08);
    }
    
    /* Account Badge - Enterprise */
    .account-badge {
        background: linear-gradient(135deg, #ecf8fb 0%, #cffafe 100%);
        padding: 1rem;
        border-radius: 10px;
        border: 2px solid #06b6d4;
        margin: 0 0 0.75rem 0;
        color: #0d4a5e;
        font-weight: 600;
        box-shadow: 0 2px 8px rgba(6, 182, 212, 0.15);
    }
    
    /* Admin Badge */
    .admin-badge {
        background: linear-gradient(135deg, #fef08a 0%, #fcd34d 100%);
        padding: 0.625rem 1rem;
        border-radius: 10px;
        border: 2px solid #ca8a04;
        font-weight: 700;
        color: #5a2e0f;
        margin: 0 0 0.75rem 0;
        box-shadow: 0 3px 10px rgba(202, 138, 4, 0.2);
        text-transform: uppercase;
        font-size: 0.75rem;
        letter-spacing: 0.05em;
        display: block;
    }
    
    /* Risk Level Badges */
    .risk-badge-critical {
        background: linear-gradient(135deg, #fee2e2 0%, #fecaca 100%);
        color: #7f1d1d;
        border: 2px solid #dc2626;
        font-weight: 700;
    }
    
    .risk-badge-high {
        background: linear-gradient(135deg, #fed7aa 0%, #fdba74 100%);
        color: #6b2410;
        border: 2px solid #ea580c;
        font-weight: 700;
    }
    
    .risk-badge-medium {
        background: linear-gradient(135deg, #fef08a 0%, #fcd34d 100%);
        color: #5a2e0f;
        border: 2px solid #ca8a04;
        font-weight: 700;
    }
    
    .risk-badge-low {
        background: linear-gradient(135deg, #dcfce7 0%, #bbf7d0 100%);
        color: #115e3b;
        border: 2px solid #16a34a;
        font-weight: 700;
    }
    
    /* Loading Spinner */
    .stSpinner > div {
        border-top-color: var(--accent-primary) !important;
    }
    
    /* Sidebar Auto-Hide and Pin Styling */
    .sidebar-pin-button {
        position: fixed;
        top: 20px;
        left: 20px;
        z-index: 999;
        background: linear-gradient(135deg, var(--primary) 0%, var(--primary-light) 100%);
        color: white;
        border: none;
        border-radius: 10px;
        padding: 0.75rem 1rem;
        font-weight: 600;
        cursor: pointer;
        box-shadow: 0 4px 12px rgba(13, 27, 42, 0.2);
        transition: all 0.3s ease;
        font-size: 0.9rem;
    }
    
    .sidebar-pin-button:hover {
        transform: translateY(-2px);
        box-shadow: 0 6px 20px rgba(13, 27, 42, 0.3);
    }
    
    /* Professional Scrollbar */
    ::-webkit-scrollbar {
        width: 12px;
        height: 12px;
    }
    
    ::-webkit-scrollbar-track {
        background: var(--neutral-100);
        border-radius: 10px;
    }
    
    ::-webkit-scrollbar-thumb {
        background: linear-gradient(180deg, var(--accent-primary), var(--accent-secondary));
        border-radius: 10px;
        border: 2px solid var(--neutral-100);
    }
    
    ::-webkit-scrollbar-thumb:hover {
        background: linear-gradient(180deg, var(--primary), var(--primary-light));
    }
    
    /* Professional Labels */
    .label-text {
        font-weight: 700;
        color: var(--primary-dark);
        font-size: 0.95rem;
        text-transform: uppercase;
        letter-spacing: 0.05em;
        margin-bottom: 0.5rem;
    }
    </style>
""", unsafe_allow_html=True)

# Session state defaults
if "user_id" not in st.session_state:
    st.session_state.user_id = None
if "user" not in st.session_state:
    st.session_state.user = None
if 'assessment_complete' not in st.session_state:
    st.session_state.assessment_complete = False
if 'threat_report' not in st.session_state:
    st.session_state.threat_report = None
if 'uploaded_files' not in st.session_state:
    st.session_state.uploaded_files = []

# Threat Modeling Frameworks
FRAMEWORKS = {
    "MITRE ATT&CK": {
        "description": "Comprehensive framework for understanding cyber adversary behavior",
        "focus": "Tactics, Techniques, and Procedures (TTPs)",
        "best_for": "Advanced threat modeling, APT analysis, comprehensive security assessments",
        "coverage": ["Initial Access", "Execution", "Persistence", "Privilege Escalation", "Defense Evasion", 
                     "Credential Access", "Discovery", "Lateral Movement", "Collection", "Exfiltration", "Impact"]
    },
    "STRIDE": {
        "description": "Microsoft's threat modeling methodology",
        "focus": "Six threat categories (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege)",
        "best_for": "Software development, API security, application security",
        "coverage": ["Spoofing Identity", "Tampering with Data", "Repudiation", "Information Disclosure", 
                     "Denial of Service", "Elevation of Privilege"]
    },
    "PASTA": {
        "description": "Process for Attack Simulation and Threat Analysis",
        "focus": "Risk-centric approach with seven stages",
        "best_for": "Risk-based threat modeling, business-aligned security",
        "coverage": ["Define Objectives", "Define Technical Scope", "Application Decomposition", 
                     "Threat Analysis", "Vulnerability Analysis", "Attack Modeling", "Risk & Impact Analysis"]
    },
    "OCTAVE": {
        "description": "Operationally Critical Threat, Asset, and Vulnerability Evaluation",
        "focus": "Organizational risk assessment",
        "best_for": "Enterprise risk management, asset-based threat modeling",
        "coverage": ["Build Asset-Based Threat Profiles", "Identify Infrastructure Vulnerabilities", 
                     "Develop Security Strategy and Plans"]
    },
    "VAST": {
        "description": "Visual, Agile, and Simple Threat modeling",
        "focus": "Scalable threat modeling for agile development",
        "best_for": "DevSecOps, continuous threat modeling, large organizations",
        "coverage": ["Application Threat Models", "Operational Threat Models", "Infrastructure Models"]
    }
}

# Placeholder for custom frameworks (disabled in UI for demo purposes)
CUSTOM_FRAMEWORKS_PREVIEW = {
    "Custom Client Framework": {
        "description": "Your organization's proprietary security assessment framework",
        "focus": "Tailored controls and risk categories specific to your industry",
        "best_for": "Organization-specific compliance, industry regulations, custom security requirements",
        "coverage": ["Custom Domain 1", "Custom Domain 2", "Custom Domain 3", "Industry-Specific Controls"],
        "status": "coming_soon",
        "activation_note": "This feature can be activated for your organization. Contact your administrator to upload your custom framework."
    }
}

# Risk Focus Areas
RISK_AREAS = {
    "Agentic AI Risk": {
        "description": "Risks from autonomous AI agents and systems",
        "threats": [
            "Prompt injection and jailbreaking",
            "Unauthorized actions by autonomous agents",
            "Model hallucinations and incorrect decisions",
            "Data poisoning and training manipulation",
            "Agent-to-agent communication security",
            "Privilege escalation by AI agents",
            "Loss of human oversight and control"
        ]
    },
    "Model Risk": {
        "description": "Risks associated with AI/ML model deployment and operations",
        "threats": [
            "Model drift and degradation",
            "Adversarial attacks on models",
            "Model inversion and extraction",
            "Bias and fairness issues",
            "Model supply chain attacks",
            "Insufficient model validation",
            "Model versioning and rollback issues"
        ]
    },
    "Data Security Risk": {
        "description": "Risks related to data confidentiality, integrity, and availability",
        "threats": [
            "Data breaches and exfiltration",
            "Unauthorized access to sensitive data",
            "Data tampering and corruption",
            "Insufficient encryption",
            "Data residency violations",
            "PII exposure",
            "Data retention and disposal issues"
        ]
    },
    "Infrastructure Risk": {
        "description": "Risks in underlying technology infrastructure",
        "threats": [
            "Cloud misconfigurations",
            "Network vulnerabilities",
            "Container and orchestration risks",
            "API security weaknesses",
            "Insufficient monitoring",
            "Denial of service vulnerabilities",
            "Third-party integration risks"
        ]
    },
    "Compliance Risk": {
        "description": "Regulatory and compliance-related risks",
        "threats": [
            "GDPR violations",
            "PCI-DSS non-compliance",
            "HIPAA violations",
            "SOX control failures",
            "Industry-specific regulation gaps",
            "Audit trail insufficiencies",
            "Data sovereignty issues"
        ]
    }
}


def get_db_session() -> Session:
    return SessionLocal()


def load_user(db: Session) -> User | None:
    if st.session_state.user_id is None:
        return None
    return db.query(User).filter(User.id == st.session_state.user_id, User.is_active == True).first()


def extract_text_from_file(uploaded_file):
    """Extract text content from uploaded files"""
    try:
        file_extension = Path(uploaded_file.name).suffix.lower()
        if file_extension in ['.txt', '.md']:
            return uploaded_file.getvalue().decode('utf-8')
        else:
            return f"[{file_extension.upper()} Document: {uploaded_file.name}]"
    except Exception as e:
        return f"[Error reading {uploaded_file.name}: {str(e)}]"


def create_pdf_download(report_content, project_name):
    """Create a PDF download using ReportLab (pure Python, no system deps)"""
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_JUSTIFY
    import re
    
    # Use Sydney timezone for PDF filename
    current_date = get_sydney_time()
    
    base = f"Threat_Assessment_{project_name.replace(' ', '_')}_{current_date.strftime('%Y%m%d')}"
    pdf_filename = f"{base}.pdf"
    
    # Create PDF buffer
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter, topMargin=0.75*inch, bottomMargin=0.75*inch,
                           leftMargin=0.75*inch, rightMargin=0.75*inch)
    
    # Styles
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        'CustomTitle',
        parent=styles['Heading1'],
        fontSize=18,
        textColor=colors.HexColor('#1a202c'),
        spaceAfter=12,
        spaceBefore=6,
        alignment=TA_CENTER,
        fontName='Helvetica-Bold'
    )
    heading1_style = ParagraphStyle(
        'CustomHeading1',
        parent=styles['Heading1'],
        fontSize=14,
        textColor=colors.HexColor('#2d3748'),
        spaceBefore=12,
        spaceAfter=6,
        fontName='Helvetica-Bold'
    )
    heading2_style = ParagraphStyle(
        'CustomHeading2',
        parent=styles['Heading2'],
        fontSize=11,
        textColor=colors.HexColor('#2c5282'),
        spaceBefore=8,
        spaceAfter=4,
        fontName='Helvetica-Bold'
    )
    body_style = ParagraphStyle(
        'CustomBody',
        parent=styles['BodyText'],
        fontSize=9,
        leading=11,
        alignment=TA_LEFT,
        spaceAfter=4
    )
    
    # Build content
    story = []
    
    # Title page
    story.append(Paragraph("Threat Assessment Report", title_style))
    story.append(Spacer(1, 0.15*inch))
    story.append(Paragraph(f"<b>Project:</b> {project_name}", body_style))
    story.append(Paragraph(f"<b>Date:</b> {current_date.strftime('%B %d, %Y')}", body_style))
    story.append(Spacer(1, 0.3*inch))
    
    # Parse markdown content
    lines = report_content.split('\n')
    current_table = []
    in_table = False
    
    i = 0
    while i < len(lines):
        line = lines[i].strip()
        
        # Skip table separator lines (---|---|---)
        if re.match(r'^[\|\s\-:]+$', line) and '|' in line:
            i += 1
            continue
        
        # Empty lines
        if not line:
            if not in_table:
                story.append(Spacer(1, 0.08*inch))
            i += 1
            continue
        
        # Headers
        if line.startswith('# ') and not line.startswith('## '):
            if current_table:
                table_element = create_reportlab_table(current_table)
                if table_element:
                    story.append(table_element)
                current_table = []
                in_table = False
            story.append(Spacer(1, 0.15*inch))
            story.append(Paragraph(line[2:], title_style))
        elif line.startswith('## ') and not line.startswith('### '):
            if current_table:
                table_element = create_reportlab_table(current_table)
                if table_element:
                    story.append(table_element)
                current_table = []
                in_table = False
            story.append(Paragraph(line[3:], heading1_style))
        elif line.startswith('### '):
            if current_table:
                table_element = create_reportlab_table(current_table)
                if table_element:
                    story.append(table_element)
                current_table = []
                in_table = False
            story.append(Paragraph(line[4:], heading2_style))
        
        # Table rows
        elif '|' in line and line.count('|') >= 2:
            in_table = True
            cells = [cell.strip() for cell in line.split('|') if cell.strip()]
            if cells:  # Only add non-empty rows
                current_table.append(cells)
        
        # Regular text
        else:
            if in_table and current_table:
                table_element = create_reportlab_table(current_table)
                if table_element:
                    story.append(table_element)
                current_table = []
                in_table = False
            
            # Format inline markdown
            line = re.sub(r'\*\*(.+?)\*\*', r'<b>\1</b>', line)
            line = re.sub(r'`(.+?)`', r'<font face="Courier" size="8">\1</font>', line)
            
            # Fix malformed HTML tags
            line = re.sub(r'<b>(CRITICAL|HIGH|MEDIUM|LOW|P0|P1|P2)<b>', r'\1', line)
            line = re.sub(r'<b>(CRITICAL|HIGH|MEDIUM|LOW|P0|P1|P2)</b>', r'\1', line)
            line = re.sub(r'<b>([^<]+)<b>', r'<b>\1</b>', line)  # Fix other malformed bold tags
            
            # Apply color formatting for risk levels in regular text
            line = re.sub(r'\b(CRITICAL)\b', r'<font color="#dc2626"><b>\1</b></font>', line)
            line = re.sub(r'\b(HIGH)\b', r'<font color="#ea580c"><b>\1</b></font>', line)
            line = re.sub(r'\b(MEDIUM)\b', r'<font color="#ca8a04"><b>\1</b></font>', line)
            line = re.sub(r'\b(LOW)\b', r'<font color="#16a34a"><b>\1</b></font>', line)
            line = re.sub(r'\b(P0)\b', r'<font color="#dc2626"><b>\1</b></font>', line)
            line = re.sub(r'\b(P1)\b', r'<font color="#ea580c"><b>\1</b></font>', line)
            line = re.sub(r'\b(P2)\b', r'<font color="#ca8a04"><b>\1</b></font>', line)
            
            # Escape special XML chars but preserve our formatting tags
            line = line.replace('&', '&amp;').replace('<b>', '<<<B>>>').replace('</b>', '<<</B>>>').replace('<font', '<<<FONT').replace('</font>', '<<</FONT>>>')
            line = line.replace('<<<B>>>', '<b>').replace('<<</B>>>', '</b>').replace('<<<FONT', '<font').replace('<<</FONT>>>', '</font>')
            
            try:
                story.append(Paragraph(line, body_style))
            except:
                # Fallback for problematic lines
                story.append(Paragraph(line.replace('<', '&lt;').replace('>', '&gt;'), body_style))
        
        i += 1
    
    # Add remaining table
    if current_table:
        table_element = create_reportlab_table(current_table)
        if table_element:
            story.append(table_element)
    
    # Build PDF
    try:
        doc.build(story)
        pdf_bytes = buffer.getvalue()
        buffer.close()
        return pdf_filename, pdf_bytes, "application/pdf"
    except Exception as e:
        buffer.close()
        # Fallback to markdown
        return f"{base}.md", report_content, "text/markdown"


def create_reportlab_table(table_data):
    """Helper to create formatted table for ReportLab"""
    from reportlab.platypus import Table, TableStyle, Paragraph
    from reportlab.lib import colors
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.lib.units import inch
    
    if not table_data or len(table_data) < 1:
        return None
    
    # Wrap cells in Paragraphs for better text wrapping
    styles = getSampleStyleSheet()
    cell_style = styles['BodyText']
    cell_style.fontSize = 7
    cell_style.leading = 9
    
    wrapped_data = []
    for row in table_data:
        wrapped_row = []
        for cell in row:
            # Clean and wrap cell text
            cell_text = str(cell).strip()
            
            # Replace markdown bold with HTML bold first
            cell_text = cell_text.replace('**', '<b>').replace('**', '</b>')
            
            # Convert risk level tags to colored text
            import re
            
            # Fix ALL malformed tags (missing closing slash) - more comprehensive patterns
            cell_text = re.sub(r'<b>([^<>]*?)<b>', r'<b>\1</b>', cell_text)  # Fix any <b>...<b> to <b>...</b>
            
            # Clean up any remaining mismatched tags
            cell_text = re.sub(r'<b>([^<>]*?)</b>', r'<b>\1</b>', cell_text)  # Ensure proper pairing
            
            # Now remove bold tags from risk level keywords so we can reapply with colors
            cell_text = re.sub(r'<b>(CRITICAL|HIGH|MEDIUM|LOW)</b>', r'\1', cell_text)
            
            # Handle compound patterns like "25-CRITICAL" or "16-HIGH"
            cell_text = re.sub(
                r'(\d+)-(CRITICAL)',
                r'\1-<font color="#dc2626" size="8"><b>\2</b></font>',
                cell_text
            )
            cell_text = re.sub(
                r'(\d+)-(HIGH)',
                r'\1-<font color="#ea580c" size="8"><b>\2</b></font>',
                cell_text
            )
            cell_text = re.sub(
                r'(\d+)-(MEDIUM)',
                r'\1-<font color="#ca8a04" size="8"><b>\2</b></font>',
                cell_text
            )
            
            # Apply color formatting for standalone risk levels
            cell_text = re.sub(
                r'\b(CRITICAL)\b',
                r'<font color="#dc2626" size="8"><b>\1</b></font>',
                cell_text
            )
            cell_text = re.sub(
                r'\b(HIGH)\b',
                r'<font color="#ea580c" size="8"><b>\1</b></font>',
                cell_text
            )
            cell_text = re.sub(
                r'\b(MEDIUM)\b',
                r'<font color="#ca8a04" size="8"><b>\1</b></font>',
                cell_text
            )
            cell_text = re.sub(
                r'\b(LOW)\b',
                r'<font color="#16a34a" size="8"><b>\1</b></font>',
                cell_text
            )
            
            # Handle P0, P1, P2 priority labels
            cell_text = re.sub(
                r'\b(P0)\b',
                r'<font color="#dc2626" size="8"><b>\1</b></font>',
                cell_text
            )
            cell_text = re.sub(
                r'\b(P1)\b',
                r'<font color="#ea580c" size="8"><b>\1</b></font>',
                cell_text
            )
            cell_text = re.sub(
                r'\b(P2)\b',
                r'<font color="#ca8a04" size="8"><b>\1</b></font>',
                cell_text
            )
            
            try:
                wrapped_row.append(Paragraph(cell_text, cell_style))
            except:
                wrapped_row.append(cell_text)
        wrapped_data.append(wrapped_row)
    
    # Calculate column widths based on content
    num_cols = len(wrapped_data[0]) if wrapped_data else 1
    available_width = 7 * inch  # Letter page width minus margins
    col_width = available_width / num_cols
    col_widths = [col_width] * num_cols
    
    # Create table with style
    table = Table(wrapped_data, colWidths=col_widths, repeatRows=1)
    
    style = TableStyle([
        # Header row
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#2d3748')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 8),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 6),
        ('TOPPADDING', (0, 0), (-1, 0), 6),
        # Body
        ('BACKGROUND', (0, 1), (-1, -1), colors.white),
        ('FONTSIZE', (0, 1), (-1, -1), 7),
        ('TOPPADDING', (0, 1), (-1, -1), 4),
        ('BOTTOMPADDING', (0, 1), (-1, -1), 4),
        ('LEFTPADDING', (0, 0), (-1, -1), 4),
        ('RIGHTPADDING', (0, 0), (-1, -1), 4),
        # Grid
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#cbd5e0')),
        # Alternate row colors
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f7fafc')])
    ])
    
    table.setStyle(style)
    return table


def get_sydney_time():
    """Get current time in Sydney, Australia timezone"""
    try:
        return datetime.now(ZoneInfo("Australia/Sydney"))
    except:
        # Fallback to UTC with offset
        return datetime.now()


def convert_to_sydney_time(utc_datetime):
    """Convert UTC datetime to Sydney timezone for display"""
    if utc_datetime is None:
        return None
    try:
        # If datetime is naive (no timezone), assume it's UTC
        if utc_datetime.tzinfo is None:
            utc_datetime = utc_datetime.replace(tzinfo=ZoneInfo("UTC"))
        # Convert to Sydney time
        return utc_datetime.astimezone(ZoneInfo("Australia/Sydney"))
    except:
        # Fallback - return as is
        return utc_datetime


def generate_threat_assessment(project_info, documents_content, framework, risk_areas, user: User, db: Session):
    """Generate comprehensive threat assessment using Claude"""
    api_key = os.getenv("ANTHROPIC_API_KEY", "")
    if not api_key or api_key.startswith("sk-ant-api03-CHANGE"):
        raise RuntimeError("Missing Anthropic API key in .env (ANTHROPIC_API_KEY)")

    client = anthropic.Anthropic(api_key=api_key)
    
    # Get current Sydney time for the report
    sydney_time = get_sydney_time()
    assessment_date = sydney_time.strftime('%B %d, %Y at %I:%M %p AEDT')
    
    # Comprehensive prompt with document evidence requirements
    prompt = f"""You are an expert cybersecurity consultant specializing in threat modeling and risk assessment. 
Perform a comprehensive threat assessment for the following project using the {framework} framework.

**PROJECT INFORMATION:**
- Project Name: {project_info['name']}
- Application Type: {project_info['app_type']}
- Deployment Model: {project_info['deployment']}
- Business Criticality: {project_info['criticality']}
- Compliance Requirements: {', '.join(project_info['compliance'])}
- Environment: {project_info['environment']}
- Assessment Date: {assessment_date}

**UPLOADED DOCUMENTATION:**
{documents_content}

**THREAT MODELING FRAMEWORK:** {framework}
{FRAMEWORKS[framework]['description']}

**SPECIFIC RISK FOCUS AREAS TO ASSESS:**
{chr(10).join([f"- {area}: {RISK_AREAS[area]['description']}" for area in risk_areas])}

**ASSESSMENT REQUIREMENTS - EVIDENCE-BASED ANALYSIS:**

Generate a professional threat assessment report with complete structure, extensive tables, and color-coded risk levels suitable for executive review.

**CRITICAL REQUIREMENT: Every finding, recommendation, and observation MUST include:**
1. **Document Reference:** Which uploaded document this observation is from
2. **Evidence Citation:** Specific quote or observation from the document
3. **Line Context:** Approximate location/section in the document
4. **Analysis:** How this evidence leads to the threat assessment finding
5. **Concrete Examples:** Specific examples from the documentation demonstrating the issue/risk

# EXECUTIVE SUMMARY

**Overall Risk Rating:** [CRITICAL/HIGH/MEDIUM/LOW]

[One paragraph describing assessment scope, methodology, and documents reviewed]

## Top 5 Critical Findings (with Document Evidence & Examples)

| Finding | Evidence Source (Doc) | Example from Docs | Risk Level | Business Impact | Timeline |
|---------|-----------------------|-------------------|-----------|-----------------|-----------|
| [Finding 1 with doc ref] | [Document: Name/Section] | [Specific example from doc] | CRITICAL | [Impact description] | Immediate (0-30 days) |
| [Finding 2 with doc ref] | [Document: Name/Section] | [Specific example from doc] | HIGH | [Impact description] | Short-term (30-90 days) |

## Key Recommendations Summary

| Priority | Count | Sample Actions |
|----------|-------|-----------------|
| P0 - CRITICAL | [count] | Immediate mitigations for critical risks |
| P1 - HIGH | [count] | High-priority security improvements |
| P2 - MEDIUM | [count] | Medium-term strengthening measures |

---

# THREAT MODELING ANALYSIS - {framework}

**Summary:** [2-3 sentence overview of the threat modeling analysis, the framework's approach, and key findings discovered during the analysis]

Comprehensive threat analysis organized by {framework} categories with risk scoring and mitigation paths, **with evidence citations and concrete examples from uploaded documentation**.

For each relevant category in {framework}, provide detailed analysis:

## [Category Name]

**Summary:** [1-2 sentences describing the threats found in this category and their overall risk level]

| Threat ID | Threat Description | Document Evidence | Example from Documentation | Likelihood | Impact | Risk Score | Recommended Mitigation |
|-----------|-------------------|-------------------|---------------------------|-----------|--------|-----------|----------------------|
| T001 | [threat description] | [Doc: Name, Section/Quote] | [Specific example from doc] | [1-5] | [1-5] | [score] | [mitigation] |

---

# SPECIALIZED RISK ASSESSMENTS

**Summary:** [2-3 sentences describing the selected risk focus areas, why they're important for this project, and the overall risk landscape across these areas]

{chr(10).join([f'''## {area}

**Summary:** [1-2 sentences describing the risk landscape for {area} based on the documentation review]

| Threat ID | Evidence Source (Doc) | Example from Docs | Threat | Likelihood | Impact | Risk Priority | Mitigation Strategy |
|-----------|-----------------------|-------------------|--------|-----------|--------|---------------|---------------------|
| T-{area[:3].upper()}-001 | [Doc: Section] | [Specific example] | [specific threat] | [1-5] | [1-5] | P0/P1/P2 | [specific action] |
''' for area in risk_areas])}

---

# COMPONENT-SPECIFIC THREAT ANALYSIS

**Summary:** [2-3 sentences describing the system architecture components analyzed and the overall security posture across different layers]

| Component | Document Evidence | Example from Docs | Critical Threats | Risk Level | Mitigation Approach |
|-----------|-------------------|-------------------|-----------------|-----------|---------------------|
| Frontend/UI | [Doc: Section] | [example from doc] | [threats] | CRITICAL/HIGH | [approach] |
| Backend/App | [Doc: Section] | [example from doc] | [threats] | CRITICAL/HIGH | [approach] |
| Database/Data | [Doc: Section] | [example from doc] | [threats] | CRITICAL/HIGH | [approach] |

---

# ATTACK SCENARIOS & KILL CHAINS

**Summary:** [2-3 sentences describing the most likely attack scenarios identified, how attackers might progress through the system, and the overall threat sophistication expected]

## Scenario 1: [Attack Title - Highest Risk Scenario from Document Evidence]

**Summary:** [1-2 sentences describing this specific attack scenario, the attacker profile, and expected impact]

| Kill Chain Phase | Document Evidence | Example from Docs | Description | Detection Window | Mitigation Strategy |
|-----------------|-------------------|-------------------|-------------|------------------|---------------------|
| Reconnaissance | [Doc: Section] | [example from doc] | [phase details] | [detection opportunity] | [mitigation] |
| Exploitation | [Doc: Section] | [example from doc] | [phase details] | [detection opportunity] | [mitigation] |
| Exfiltration | [Doc: Section] | [example from doc] | [phase details] | [detection opportunity] | [mitigation] |

---

# COMPREHENSIVE RISK MATRIX

**Summary:** [2-3 sentences explaining the risk scoring methodology, how likelihood and impact are calculated, and the overall risk distribution across findings]

## Risk Score Calculation

| Likelihood (L) | 1 - Rare | 2 - Unlikely | 3 - Possible | 4 - Likely | 5 - Very Likely |
|---|---|---|---|---|---|
| **5 - Catastrophic** | 5 | 10 | 15 | 20 | **25-CRITICAL** |
| **4 - Major** | 4 | 8 | 12 | **16-HIGH** | **20-CRITICAL** |
| **3 - Moderate** | 3 | 6 | **9-MEDIUM** | **12-HIGH** | **15-HIGH** |

## All Findings Risk Matrix

| Finding ID | Description | Likelihood | Impact | Risk Score | Risk Level | Priority | Owner | Remediation Timeline |
|----------|-------------|-----------|--------|-----------|-----------|----------|-------|----------------------|
| F001 | [critical finding] | [1-5] | [1-5] | [score] | **CRITICAL** | P0 | [owner] | 0-30 days |

---

# PRIORITIZED RECOMMENDATIONS

**Summary:** [2-3 sentences describing the remediation strategy, prioritization approach, and expected timeline for implementation]

## P0 - CRITICAL (Remediate in 0-30 days)

**These findings represent immediate threats requiring urgent action.**

| Rec ID | Recommendation | Current Risk | Risk Reduction | Implementation Steps | Required Effort | Owner | Target Completion |
|--------|---------------|--------------|----------------|---------------------|-----------------|-------|------------------|
| R001 | [action] | Critical | [% reduction] | [step 1, 2, 3...] | [effort estimate] | [owner] | [date] |

## P1 - HIGH (Remediate in 30-90 days)

**High-priority improvements that significantly reduce risk exposure.**

| Rec ID | Recommendation | Current Risk | Risk Reduction | Implementation Steps | Required Effort | Owner | Target Completion |
|--------|---------------|--------------|----------------|---------------------|-----------------|-------|------------------|
| R010 | [action] | High | [% reduction] | [step 1, 2, 3...] | [effort estimate] | [owner] | [date] |

---

# SECURITY CONTROLS MAPPING

**Summary:** [2-3 sentences describing the security controls framework used, how controls map to findings, and the overall control maturity]

| Control Category | Control Name | Implementation Status | Addresses Finding | Compliance Requirement | Timeline |
|-----------------|--------------|----------------------|-------------------|----------------------|----------|
| Preventive | [control] | [Not Started/In Progress/Implemented] | [F-ID] | [framework] | [timeline] |
| Detective | [control] | [Not Started/In Progress/Implemented] | [F-ID] | [framework] | [timeline] |

---

# COMPLIANCE CONSIDERATIONS

**Summary:** [2-3 sentences describing the compliance requirements, current gaps identified, and timeline for achieving compliance]

| Finding ID | Finding | Compliance Requirement | Compliance Gap | Required Evidence | Remediation Timeline |
|----------|---------|----------------------|----------------|------------------|---------------------|
{chr(10).join([f"| [F-ID] | [finding] | {req} | [gap description] | [evidence needed] | [timeline] |" for req in project_info['compliance']])}

---

# REFERENCES

**Threat Modeling Frameworks:**
- **{framework}** - {FRAMEWORKS[framework]['description']}
  - Focus: {FRAMEWORKS[framework]['focus']}
  - Coverage: {', '.join(FRAMEWORKS[framework]['coverage'][:3])}...

**Security Standards & Guidelines:**
- [NIST SP 800-53 Rev 5](https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final) - Security and Privacy Controls for Information Systems and Organizations
- [OWASP Top 10 2021](https://owasp.org/www-project-top-ten/) - Top 10 Web Application Security Risks
- [MITRE ATT&CK Framework](https://attack.mitre.org/) - Adversary Tactics, Techniques, and Common Knowledge
- [CIS Critical Security Controls v8](https://www.cisecurity.org/controls/v8) - Critical Security Controls for Effective Cyber Defense
- [ISO/IEC 27001:2013](https://www.iso.org/standard/54534.html) - Information Security Management Systems Requirements

**Compliance Frameworks:**
{chr(10).join([f"- **{req}** - Regulatory compliance framework" for req in project_info['compliance']])}

**Risk Assessment Methodologies:**
- [CVSS v3.1](https://www.first.org/cvss/v3.1/specification-document) - Common Vulnerability Scoring System
- [FAIR](https://www.fairinstitute.org/) - Factor Analysis of Information Risk
- [NIST Risk Management Framework (RMF)](https://csrc.nist.gov/projects/risk-management/about-rmf) - NIST Risk Management Framework

**Additional Resources:**
- [CERT Secure Coding Standards](https://wiki.sei.cmu.edu/confluence/display/seccode) - Carnegie Mellon SEI Secure Coding
- [SANS Top 25 Most Dangerous Software Errors](https://www.sans.org/top25-software-errors/) - SANS CWE Top 25
- [Cloud Security Alliance (CSA) Cloud Controls Matrix](https://cloudsecurityalliance.org/research/cloud-controls-matrix/) - CSA CCM
- [ENISA Threat Landscape Reports](https://www.enisa.europa.eu/topics/threat-risk-management/threats-and-trends) - European Union Agency for Cybersecurity

---

# DISCLAIMER

**AI-Generated Report Notice:**

This threat assessment report was generated using artificial intelligence (AI) technology powered by SecureAI. While the analysis incorporates industry-standard frameworks, best practices, and uploaded documentation, it should be considered as a preliminary assessment tool.

**Important Considerations:**
- This report is AI-generated and may contain inaccuracies, omissions, or misinterpretations
- All findings, risk ratings, and recommendations must be validated by qualified security professionals
- The assessment should be reviewed and supplemented with manual security analysis
- Implementation of any recommendations should be evaluated in the context of your specific environment
- This report does not replace professional security audits, penetration testing, or compliance assessments

**Recommended Next Steps:**
1. Review this report with your security team and subject matter experts
2. Validate findings against your actual system architecture and controls
3. Conduct additional manual threat modeling sessions
4. Perform security testing to confirm identified vulnerabilities
5. Engage certified security professionals for critical systems

By using this AI-generated report, you acknowledge that it serves as a starting point for threat modeling activities and requires human expertise for validation and implementation.

**CRITICAL FORMATTING REQUIREMENTS:**

1. **Table Usage:** All findings, recommendations, risk matrices MUST use markdown tables
2. **Color-Coded Risk Levels:** Always use **CRITICAL** (red), **HIGH** (orange), **MEDIUM** (yellow), **LOW** (green)
3. **Unique Identifiers:** Use F### for findings, R### for recommendations, T### for threats
4. **Professional Tone:** Executive summary suitable for C-level review
5. **Document References:** Every finding must reference the source document

Generate the complete, detailed, professionally formatted threat assessment report now."""

    message = client.messages.create(
        model="claude-sonnet-4-20250514",
        max_tokens=16000,
        messages=[{"role": "user", "content": prompt}]
    )

    report = message.content[0].text if message.content else "No content returned"

    # Calculate risk counts once and cache them
    report_upper = report.upper()
    critical_count = report_upper.count("CRITICAL")
    high_count = report_upper.count("HIGH")
    medium_count = report_upper.count("MEDIUM")

    # Save to database with cached risk counts
    assessment = ThreatAssessment(
        organization_id=user.organization_id,
        user_id=user.id,
        project_name=project_info['name'],
        project_number=project_info.get('number', None),
        framework=framework,
        risk_type=', '.join(risk_areas[:3]),
        system_description=documents_content[:500],
        assessment_report=report,
        report_html=report,
        report_meta={"framework": framework, "risk_areas": risk_areas},
        uploaded_files=[f.name for f in st.session_state.get('current_uploaded_files', [])],
        status="completed",
        critical_count=critical_count,
        high_count=high_count,
        medium_count=medium_count
    )
    db.add(assessment)
    db.commit()
    db.refresh(assessment)
    return report, assessment


def render_login(db: Session):
    col1, col2, col3 = st.columns([1, 2, 1])
    with col2:
        st.markdown("# 🔒 AI Threat Modeling Tool")
        st.markdown("### Sign in to continue")
        
        email = st.text_input("Email", placeholder="admin@example.com")
        password = st.text_input("Password", type="password", placeholder="Your password")
        
        if st.button("Sign In", type="primary", use_container_width=True):
            if not email or not password:
                st.warning("Please enter both email and password")
                return
            user = PasswordAuth.authenticate(email=email, password=password, db=db)
            if user:
                st.session_state.user_id = user.id
                st.session_state.user = user
                st.success(f"Welcome back, {user.full_name or user.email}!")
                # Clear SecureAI key on login to avoid storing it
                st.session_state.api_key_input = ""
                try:
                    os.environ.pop("ANTHROPIC_API_KEY", None)
                except Exception:
                    pass
                st.rerun()
            else:
                st.error("Invalid credentials")
        
        st.caption("Default: admin@example.com / admin123")


def render_sidebar(user: User):
    # Sidebar Pin Toggle Button (always visible)
    with st.sidebar:
        # Compact Header with Pin Button
        col1, col2 = st.columns([4, 1])
        with col2:
            if st.button("📌" if st.session_state.sidebar_pinned else "📍", key="pin_toggle", help="Pin/Unpin sidebar", use_container_width=True):
                st.session_state.sidebar_pinned = not st.session_state.sidebar_pinned
        
        # Enterprise Logo/Brand Section - Optimized Spacing
        st.markdown("""
            <div style="
                background: linear-gradient(135deg, #0d1b2a 0%, #1a2f4a 100%);
                padding: 1.5rem 1.25rem;
                border-radius: 14px;
                margin: 0.75rem 0 1.5rem 0;
                text-align: center;
                color: white;
                box-shadow: 0 4px 16px rgba(13, 27, 42, 0.25);
                border: 1px solid rgba(8, 145, 178, 0.25);
                position: relative;
                overflow: hidden;
            ">
                <div style="position: relative; z-index: 2;">
                    <h3 style="color: white !important; margin: 0 0 0.5rem 0; font-size: 1.4rem; font-weight: 800; letter-spacing: -0.01em;">🛡️ SecureAI</h3>
                    <div style="height: 2px; background: linear-gradient(90deg, #0891b2, #06b6d4); margin: 0.5rem 0; border-radius: 10px;"></div>
                    <p style="color: rgba(255,255,255,0.9); margin: 0.5rem 0 0 0; font-size: 0.8rem; font-weight: 600; letter-spacing: 0.02em;">Assessment Platform</p>
                </div>
            </div>
        """, unsafe_allow_html=True)
        
        # Account Section - Compact
        st.markdown("""
            <div style="margin-bottom: 1.25rem;">
                <p style="font-size: 0.75rem; color: #64748b; text-transform: uppercase; letter-spacing: 0.1em; font-weight: 700; margin: 0 0 0.5rem 0;">Account</p>
            </div>
        """, unsafe_allow_html=True)
        
        st.markdown(f"""
            <div class="account-badge" style="margin: 0 0 0.75rem 0; padding: 1rem;">
                <div style="font-size: 0.75rem; color: #0d4a5e; text-transform: uppercase; letter-spacing: 0.05em; font-weight: 700; margin-bottom: 0.375rem;">Email</div>
                <div style="font-size: 0.95rem; font-weight: 700; color: #0d4a5e; word-break: break-all;">{user.email}</div>
            </div>
        """, unsafe_allow_html=True)
        
        if user.is_org_admin or user.role == "super_admin":
            st.markdown('<div class="admin-badge" style="margin: 0; padding: 0.625rem 1rem; font-size: 0.75rem;">🔑 Administrator</div>', unsafe_allow_html=True)
        
        st.markdown("---")
        
        # API Configuration - Compact
        st.markdown("""
            <p style="font-size: 0.75rem; color: #64748b; text-transform: uppercase; letter-spacing: 0.1em; font-weight: 700; margin: 0 0 0.75rem 0;">API Configuration</p>
        """, unsafe_allow_html=True)
        
        # Get current API key from environment
        current_key = os.getenv("ANTHROPIC_API_KEY", "")
        is_placeholder = current_key.startswith("sk-ant-api03-CHANGE")
        
        if is_placeholder or not current_key:
            st.warning("API key not configured", icon="⚠️")
        else:
            st.success("API key active", icon="✅")
        
        # API Key input - Compact
        if 'api_key_input' not in st.session_state:
            st.session_state.api_key_input = current_key if not is_placeholder else ""
        
        api_key = st.text_input(
            "API Key",
            type="password",
            value=st.session_state.api_key_input,
            placeholder="sk-ant-api03-...",
            label_visibility="collapsed"
        )
        
        if api_key and api_key != st.session_state.api_key_input:
            st.session_state.api_key_input = api_key
            os.environ["ANTHROPIC_API_KEY"] = api_key
            st.success("Key updated", icon="✅")

        # Storage Options - Compact
        save_toggle = st.checkbox("Save key", value=False, help="Store in .env file")
        
        col1, col2 = st.columns(2)
        with col1:
            if st.button("Save", use_container_width=True, key="save_key_btn"):
                if not api_key:
                    st.error("Enter key first", icon="❌")
                elif not save_toggle:
                    st.warning("Enable save first", icon="⚠️")
                else:
                    try:
                        from pathlib import Path
                        env_path = Path(__file__).parent / ".env"
                        content = ""
                        if env_path.exists():
                            content = env_path.read_text(encoding="utf-8")
                        lines = content.splitlines() if content else []
                        written = False
                        new_lines = []
                        for line in lines:
                            if line.strip().startswith("ANTHROPIC_API_KEY="):
                                new_lines.append(f"ANTHROPIC_API_KEY={api_key}")
                                written = True
                            else:
                                new_lines.append(line)
                        if not written:
                            new_lines.append(f"ANTHROPIC_API_KEY={api_key}")
                        env_path.write_text("\n".join(new_lines) + "\n", encoding="utf-8")
                        os.environ["ANTHROPIC_API_KEY"] = api_key
                        st.success("Saved", icon="✅")
                    except Exception as e:
                        st.error(f"Error: {str(e)[:30]}")
        
        with col2:
            if st.button("Clear", use_container_width=True, key="clear_key_btn"):
                st.session_state.api_key_input = ""
                os.environ.pop("ANTHROPIC_API_KEY", None)
                st.info("Cleared", icon="🔄")
        
        st.markdown("---")
        
        
        # Help & Support Section
        st.markdown("### 📚 Help & Support")
        st.markdown("""
            <div style="background: #f9fafb; padding: 1.25rem; border-radius: 12px; border: 2px solid var(--neutral-200);">
                <p style="font-size: 0.9rem; color: var(--neutral-600); margin: 0 0 0.5rem 0;">
                    <strong>Need help?</strong> Contact support@secureai.example.com
                </p>
                <p style="font-size: 0.85rem; color: var(--neutral-600); margin: 0.75rem 0 0 0;">
                    📖 <a href="#" style="color: var(--accent-primary); text-decoration: none; font-weight: 600;">Documentation</a>
                </p>
            </div>
        """, unsafe_allow_html=True)
        
        st.markdown("---")
        
        if st.button("🚪 Sign Out", use_container_width=True):
            # Clear SecureAI key on logout
            st.session_state.api_key_input = ""
            try:
                os.environ.pop("ANTHROPIC_API_KEY", None)
            except Exception:
                pass
            st.session_state.user_id = None
            st.session_state.user = None
            st.rerun()


def render_threat_assessment_form(db: Session, user: User):
    """Render the comprehensive threat assessment form"""
    # Quick actions
    qa_col1, qa_col2 = st.columns([3, 1])
    with qa_col2:
        if st.button("➕ New Assessment", key="new_assessment_top", use_container_width=True):
            st.session_state.assessment_complete = False
            st.session_state.threat_report = None
            st.session_state.current_project_name = None
            st.session_state.current_assessment_id = None
            st.session_state.current_uploaded_files = []
            # Reset all form fields (exclude widget keys like uploaded_files)
            form_keys = [
                "project_name", "project_number", "app_type", "deployment", "criticality", 
                "compliance", "environment"
            ]
            for key in form_keys:
                if key in st.session_state:
                    del st.session_state[key]
            # Reset framework and risk selections
            for k in list(st.session_state.keys()):
                if k.startswith("framework_") or k.startswith("risk_"):
                    del st.session_state[k]
            st.rerun()

    # Header
    st.markdown("## 📊 Project Information")
    
    col1, col2 = st.columns(2)
    with col1:
        project_name = st.text_input("Project Name *", placeholder="e.g., Customer Portal Application", key="project_name")
        project_number = st.text_input("Project Number", placeholder="e.g., PRJ-2026-001", key="project_number", help="Optional: Project number for version tracking")
        app_type = st.selectbox("Application Type *", 
            ["Web Application", "Mobile Application", "API/Microservice", 
             "Desktop Application", "Cloud Service", "IoT System", "AI/ML Platform"],
            key="app_type")
        deployment = st.selectbox("Deployment Model *",
            ["Cloud (AWS)", "Cloud (Azure)", "Cloud (GCP)", "Cloud (Multi-Cloud)",
             "On-Premises", "Hybrid", "Edge Computing"],
            key="deployment")
    
    with col2:
        criticality = st.selectbox("Business Criticality *", ["Critical", "High", "Medium", "Low"], key="criticality")
        compliance = st.multiselect("Compliance Requirements",
            ["PCI-DSS", "GDPR", "HIPAA", "SOX", "ISO 27001", "SOC 2", "NIST", "FedRAMP"],
            key="compliance")
        environment = st.selectbox("Environment", ["Production", "Staging", "Development", "UAT", "DR/Backup"], key="environment")
    
    # Upload Documents
    st.markdown("## 📁 Upload Project Documents")
    st.markdown('<div class="upload-box"><h3>📤 Drop your files here</h3><p>Architecture diagrams, design docs, data flows, API specs</p></div>', unsafe_allow_html=True)
    
    uploaded_files = st.file_uploader(
        "Choose files",
        accept_multiple_files=True,
        type=['pdf', 'docx', 'txt', 'md', 'png', 'jpg', 'jpeg', 'yaml', 'json'],
        label_visibility="collapsed",
        key="uploaded_files"
    )
    
    if uploaded_files:
        st.success(f"✓ {len(uploaded_files)} file(s) uploaded")
        st.session_state.current_uploaded_files = uploaded_files
    
    # Framework Selection
    st.markdown("## 🎯 Select Threat Modeling Framework")
    st.markdown('<p style="color: #666; margin-bottom: 1rem;">Choose the framework that best fits your threat modeling needs</p>', unsafe_allow_html=True)
    
    framework_cols = st.columns(2)
    selected_framework = None
    
    # Display active frameworks
    for idx, (framework, details) in enumerate(FRAMEWORKS.items()):
        col = framework_cols[idx % 2]
        with col:
            is_selected = st.checkbox(framework, key=f"framework_{framework}", help=details['description'])
            if is_selected:
                selected_framework = framework
                st.markdown(f"""
                <div class='framework-card selected'>
                    <h4>{framework}</h4>
                    <p><strong>Focus:</strong> {details['focus']}</p>
                    <p><strong>Best For:</strong> {details['best_for']}</p>
                </div>
                """, unsafe_allow_html=True)
            else:
                st.markdown(f"""
                <div class='framework-card'>
                    <h4>{framework}</h4>
                    <p>{details['description'][:100]}...</p>
                </div>
                """, unsafe_allow_html=True)
    
    # Display custom framework preview (disabled)
    for idx, (framework, details) in enumerate(CUSTOM_FRAMEWORKS_PREVIEW.items()):
        col = framework_cols[(len(FRAMEWORKS) + idx) % 2]
        with col:
            st.checkbox(
                framework, 
                key=f"framework_custom_{framework}", 
                disabled=True,
                help=details['activation_note']
            )
            st.markdown(f"""
            <div class='framework-card disabled'>
                <h4>{framework} <span class='coming-soon-badge'>Coming Soon</span></h4>
                <p><strong>Focus:</strong> {details['focus']}</p>
                <p><strong>Best For:</strong> {details['best_for']}</p>
                <div class='activation-note'>
                    💡 {details['activation_note']}
                </div>
            </div>
            """, unsafe_allow_html=True)
    
    # Risk Focus Areas
    st.markdown("## 🎲 Select Risk Focus Areas")
    st.markdown('<p style="color: #666; margin-bottom: 1rem;">Choose specific risk areas for detailed analysis</p>', unsafe_allow_html=True)
    
    selected_risks = []
    risk_cols = st.columns(2)
    
    for idx, (risk_area, details) in enumerate(RISK_AREAS.items()):
        col = risk_cols[idx % 2]
        with col:
            is_selected = st.checkbox(risk_area, value=True, key=f"risk_{risk_area}")
            if is_selected:
                selected_risks.append(risk_area)
                with st.expander(f"📋 Threats in {risk_area}"):
                    for threat in details['threats']:
                        st.markdown(f"- {threat}")
    
    # Generate Assessment
    st.markdown("## 🚀 Generate Threat Assessment")
    
    can_generate = project_name and selected_framework and len(selected_risks) > 0 and uploaded_files
    
    if not can_generate:
        missing = []
        if not project_name: missing.append("✗ Project Name")
        if not selected_framework: missing.append("✗ Framework")
        if len(selected_risks) == 0: missing.append("✗ Risk Areas")
        if not uploaded_files: missing.append("✗ Documents")
        st.warning(f"Complete: {', '.join(missing)}")
    else:
        st.success("✓ All fields complete - Ready to generate!")
    
    if st.button("🎯 Generate Threat Assessment Report", disabled=not can_generate, use_container_width=True):
        with st.spinner("Generating comprehensive assessment with SecureAI..."):
            try:
                documents_content = ""
                for file in uploaded_files:
                    content = extract_text_from_file(file)
                    documents_content += f"\n\n### {file.name}\n{content}"
                
                project_info = {
                    'name': project_name,
                    'number': st.session_state.get('project_number', ''),
                    'app_type': app_type,
                    'deployment': deployment,
                    'criticality': criticality,
                    'compliance': compliance or ['None'],
                    'environment': environment
                }
                
                report, assessment = generate_threat_assessment(
                    project_info, documents_content, selected_framework, selected_risks, user, db
                )
                
                st.session_state.threat_report = report
                st.session_state.current_project_name = project_name
                st.session_state.current_assessment_id = assessment.id
                st.session_state.assessment_complete = True
                st.balloons()
                st.success("✅ Comprehensive threat assessment generated!")
                st.rerun()
            except Exception as e:
                st.error(f"Error: {str(e)}")
    
    # Display Results
    if st.session_state.assessment_complete and st.session_state.threat_report:
        st.markdown("---")
        st.markdown("## 📋 Threat Assessment Report")
        
        project_name_display = st.session_state.get('current_project_name', 'Project')
        
        col1, col2, col3 = st.columns([1.5, 1.5, 1])
        with col1:
            # PDF Download
            filename, content, mime = create_pdf_download(
                st.session_state.threat_report,
                project_name_display
            )
            st.download_button(
                "📥 Download as PDF" if mime == "application/pdf" else "📥 Download Report",
                content,
                file_name=filename,
                mime=mime,
                use_container_width=True
            )
            if mime != "application/pdf":
                st.caption("⚠️ PDF generation requires weasyprint. Downloading as Markdown.")
        
        with col2:
            # Markdown Download - use current date with timezone support
            try:
                current_date = datetime.now(ZoneInfo("Australia/Sydney"))
            except:
                current_date = datetime.now()
            md_filename = f"Threat_Assessment_{project_name_display.replace(' ', '_')}_{current_date.strftime('%Y%m%d')}.md"
            st.download_button(
                "📄 Download as Markdown",
                st.session_state.threat_report,
                file_name=md_filename,
                mime="text/markdown",
                use_container_width=True
            )
        
        with col3:
            if st.button("🔄 New Assessment", use_container_width=True):
                st.session_state.assessment_complete = False
                st.session_state.threat_report = None
                st.session_state.current_project_name = None
                st.session_state.current_assessment_id = None
                st.session_state.current_uploaded_files = []
                # Reset all form fields
                form_keys = [
                    "project_name", "app_type", "deployment", "criticality", 
                    "compliance", "environment", "uploaded_files"
                ]
                for key in form_keys:
                    if key in st.session_state:
                        del st.session_state[key]
                # Reset framework and risk selections
                for k in list(st.session_state.keys()):
                    if k.startswith("framework_") or k.startswith("risk_"):
                        del st.session_state[k]
                st.rerun()
        
        st.markdown("---")
        with st.expander("📖 Full Report Content", expanded=True):
            st.markdown(st.session_state.threat_report)


def render_past_assessments(db: Session, user: User):
    """Render past assessments with filters, project grouping, and version history"""
    st.markdown("# 📚 Past Assessments")
    st.markdown('<p style="color: #64748b; font-size: 1.05rem; margin-bottom: 2rem;">View and manage all your threat assessment reports with version history</p>', unsafe_allow_html=True)
    
    # Get summary metrics using efficient database queries
    from sqlalchemy import func, distinct
    from datetime import timedelta
    
    total_count = db.query(func.count(ThreatAssessment.id)).filter(ThreatAssessment.user_id == user.id).scalar()
    
    if total_count == 0:
        st.info("🔍 No past assessments yet. Create your first threat assessment in the 'Threat Modeling' tab!")
        return
    
    # Summary metrics using database aggregation
    metric_col1, metric_col2, metric_col3, metric_col4 = st.columns(4)
    with metric_col1:
        st.metric("📊 Total Assessments", total_count)
    with metric_col2:
        completed = db.query(func.count(ThreatAssessment.id)).filter(
            ThreatAssessment.user_id == user.id,
            ThreatAssessment.status == "completed"
        ).scalar()
        st.metric("✅ Completed", completed)
    with metric_col3:
        sydney_now = get_sydney_time()
        cutoff_date = sydney_now - timedelta(days=7)
        recent = db.query(func.count(ThreatAssessment.id)).filter(
            ThreatAssessment.user_id == user.id,
            ThreatAssessment.created_at >= cutoff_date
        ).scalar()
        st.metric("🕐 Last 7 Days", recent)
    with metric_col4:
        unique_projects = db.query(func.count(distinct(ThreatAssessment.project_number))).filter(
            ThreatAssessment.user_id == user.id,
            ThreatAssessment.project_number.isnot(None),
            ThreatAssessment.project_number != ""
        ).scalar()
        st.metric("🔢 Unique Projects", unique_projects)
    
    st.markdown("<br>", unsafe_allow_html=True)
    
    # View Mode Toggle
    view_mode = st.radio(
        "View Mode", 
        ["📋 All Assessments", "📊 Group by Project Number"],
        horizontal=True,
        help="Switch between viewing all assessments or grouping by project number"
    )
    
    st.markdown("<br>", unsafe_allow_html=True)
    
    # Cache filter options to avoid querying on every rerun
    @st.cache_data(ttl=300)  # Cache for 5 minutes
    def get_filter_options(user_id):
        """Get unique values for filter dropdowns"""
        from sqlalchemy import distinct
        
        frameworks_query = db.query(distinct(ThreatAssessment.framework)).filter(
            ThreatAssessment.user_id == user_id,
            ThreatAssessment.framework.isnot(None)
        ).order_by(ThreatAssessment.framework).all()
        frameworks = [f[0] for f in frameworks_query]
        
        risk_types_query = db.query(distinct(ThreatAssessment.risk_type)).filter(
            ThreatAssessment.user_id == user_id,
            ThreatAssessment.risk_type.isnot(None)
        ).order_by(ThreatAssessment.risk_type).all()
        risk_types = [r[0] for r in risk_types_query]
        
        return frameworks, risk_types
    
    frameworks, risk_types = get_filter_options(user.id)
    
    # Filters - Initialize defaults only
    if "framework_filter" not in st.session_state:
        st.session_state.framework_filter = "All"
    if "risk_filter" not in st.session_state:
        st.session_state.risk_filter = "All"
    if "status_filter" not in st.session_state:
        st.session_state.status_filter = "All"
    if "date_filter" not in st.session_state:
        st.session_state.date_filter = "All Time"
    
    st.markdown("### 🔎 Filter Assessments")
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        framework_options = ["All"] + frameworks
        framework_filter = st.selectbox("Framework", framework_options, index=framework_options.index(st.session_state.framework_filter) if st.session_state.framework_filter in framework_options else 0, key="framework_filter")
    
    with col2:
        risk_options = ["All"] + risk_types
        risk_filter = st.selectbox("Risk Type", risk_options, index=risk_options.index(st.session_state.risk_filter) if st.session_state.risk_filter in risk_options else 0, key="risk_filter")
    
    with col3:
        status_options = ["All", "completed", "draft", "in_progress"]
        status_filter = st.selectbox("Status", status_options, index=status_options.index(st.session_state.status_filter) if st.session_state.status_filter in status_options else 0, key="status_filter")
    
    with col4:
        date_options = ["All Time", "Last 7 Days", "Last 30 Days", "Last 90 Days"]
        date_filter = st.selectbox("Date Range", date_options, index=date_options.index(st.session_state.date_filter) if st.session_state.date_filter in date_options else 0, key="date_filter")
    
    # Build query with filters at database level
    query = db.query(ThreatAssessment).filter(ThreatAssessment.user_id == user.id)
    
    if framework_filter != "All":
        query = query.filter(ThreatAssessment.framework == framework_filter)
    
    if risk_filter != "All":
        query = query.filter(ThreatAssessment.risk_type == risk_filter)
    
    if status_filter != "All":
        query = query.filter(ThreatAssessment.status == status_filter)
    
    if date_filter != "All Time":
        days_map = {"Last 7 Days": 7, "Last 30 Days": 30, "Last 90 Days": 90}
        sydney_now = get_sydney_time()
        cutoff = sydney_now - timedelta(days=days_map[date_filter])
        query = query.filter(ThreatAssessment.created_at >= cutoff)
    
    # Get filtered count and assessments
    filtered_count = query.count()
    filtered_assessments = query.order_by(ThreatAssessment.created_at.desc()).all()
    
    # Display count
    st.markdown(f'<p style="color: #64748b; font-weight: 600; margin: 1.5rem 0 1rem 0;">Showing {filtered_count} of {total_count} assessments</p>', unsafe_allow_html=True)
    
    if not filtered_assessments:
        st.info("No assessments match the selected filters.")
        return
    
    # Display based on view mode
    if view_mode == "📊 Group by Project Number":
        # Group assessments by project number
        from collections import defaultdict
        project_groups = defaultdict(list)
        
        for assessment in filtered_assessments:
            proj_num = assessment.project_number if assessment.project_number else "No Project Number"
            project_groups[proj_num].append(assessment)
        
        # Display each project group
        for proj_num in sorted(project_groups.keys(), key=lambda x: (x == "No Project Number", x)):
            assessments_in_project = sorted(project_groups[proj_num], key=lambda x: x.created_at, reverse=True)
            
            # Project header
            st.markdown(f"""
            <div style="
                background: linear-gradient(135deg, #0891b2 0%, #06b6d4 100%);
                padding: 1rem 1.5rem;
                border-radius: 12px;
                margin: 1.5rem 0 1rem 0;
                box-shadow: 0 4px 12px rgba(8, 145, 178, 0.2);
            ">
                <h3 style="margin: 0; color: white; font-weight: 700; font-size: 1.4rem;">
                    📁 Project: {proj_num}
                </h3>
                <p style="margin: 0.5rem 0 0 0; color: rgba(255, 255, 255, 0.9); font-size: 0.95rem;">
                    {len(assessments_in_project)} version{'' if len(assessments_in_project) == 1 else 's'} • 
                    Latest: {convert_to_sydney_time(assessments_in_project[0].created_at).strftime('%B %d, %Y at %I:%M %p')}
                </p>
            </div>
            """, unsafe_allow_html=True)
            
            # Version history table
            st.markdown("#### 📜 Version History")
            
            # Create a version table
            for idx, assessment in enumerate(assessments_in_project, 1):
                version_number = len(assessments_in_project) - idx + 1
                
                # Use cached risk counts (much faster than parsing report text)
                critical_count = assessment.critical_count or 0
                high_count = assessment.high_count or 0
                medium_count = assessment.medium_count or 0
                
                # Version card with collapsible details
                with st.expander(
                    f"🔖 Version {version_number} - {assessment.project_name} ({convert_to_sydney_time(assessment.created_at).strftime('%b %d, %Y at %I:%M %p AEDT')})",
                    expanded=(idx == 0)
                ):
                    col_info1, col_info2, col_info3 = st.columns(3)
                    
                    with col_info1:
                        st.markdown(f"""
                        <div style="background: #f9fafb; padding: 0.75rem; border-radius: 8px; border: 1px solid #e5e7eb;">
                            <p style="color: #64748b; font-size: 0.8rem; margin: 0; font-weight: 600;">FRAMEWORK</p>
                            <p style="color: #0f172a; margin: 0.25rem 0 0 0; font-weight: 600; font-size: 0.95rem;">{assessment.framework}</p>
                        </div>
                        """, unsafe_allow_html=True)
                    
                    with col_info2:
                        st.markdown(f"""
                        <div style="background: #f9fafb; padding: 0.75rem; border-radius: 8px; border: 1px solid #e5e7eb;">
                            <p style="color: #64748b; font-size: 0.8rem; margin: 0; font-weight: 600;">STATUS</p>
                            <p style="color: #0f172a; margin: 0.25rem 0 0 0; font-weight: 600; font-size: 0.95rem;">{assessment.status.upper()}</p>
                        </div>
                        """, unsafe_allow_html=True)
                    
                    with col_info3:
                        st.markdown(f"""
                        <div style="background: #f9fafb; padding: 0.75rem; border-radius: 8px; border: 1px solid #e5e7eb;">
                            <p style="color: #64748b; font-size: 0.8rem; margin: 0; font-weight: 600;">RISK AREAS</p>
                            <p style="color: #0f172a; margin: 0.25rem 0 0 0; font-weight: 600; font-size: 0.85rem;">{assessment.risk_type[:30] if assessment.risk_type else 'N/A'}...</p>
                        </div>
                        """, unsafe_allow_html=True)
                    
                    st.markdown("<br>", unsafe_allow_html=True)
                    
                    # Display uploaded documents
                    if assessment.uploaded_files:
                        st.markdown("**📄 Documents Used:**")
                        docs_list = assessment.uploaded_files if isinstance(assessment.uploaded_files, list) else []
                        if docs_list:
                            for doc_name in docs_list:
                                st.markdown(f"- {doc_name}")
                        else:
                            st.caption("No documents recorded")
                    
                    st.markdown("<br>", unsafe_allow_html=True)
                    
                    # Risk metrics
                    risk_col1, risk_col2, risk_col3 = st.columns(3)
                    with risk_col1:
                        st.markdown(f"""
                        <div style="background: linear-gradient(135deg, #fee2e2 0%, #fecaca 100%); padding: 0.75rem; border-radius: 10px; text-align: center; border: 1px solid #fecaca;">
                            <p style="color: #991b1b; font-size: 0.75rem; margin: 0; font-weight: 700;">🔴 CRITICAL</p>
                            <p style="color: #991b1b; font-size: 1.5rem; margin: 0.25rem 0 0 0; font-weight: 800;">{critical_count}</p>
                        </div>
                        """, unsafe_allow_html=True)
                    
                    with risk_col2:
                        st.markdown(f"""
                        <div style="background: linear-gradient(135deg, #fed7aa 0%, #fdba74 100%); padding: 0.75rem; border-radius: 10px; text-align: center; border: 1px solid #fdba74;">
                            <p style="color: #9a3412; font-size: 0.75rem; margin: 0; font-weight: 700;">🟠 HIGH</p>
                            <p style="color: #9a3412; font-size: 1.5rem; margin: 0.25rem 0 0 0; font-weight: 800;">{high_count}</p>
                        </div>
                        """, unsafe_allow_html=True)
                    
                    with risk_col3:
                        st.markdown(f"""
                        <div style="background: linear-gradient(135deg, #fef3c7 0%, #fde68a 100%); padding: 0.75rem; border-radius: 10px; text-align: center; border: 1px solid #fde68a;">
                            <p style="color: #92400e; font-size: 0.75rem; margin: 0; font-weight: 700;">🟡 MEDIUM</p>
                            <p style="color: #92400e; font-size: 1.5rem; margin: 0.25rem 0 0 0; font-weight: 800;">{medium_count}</p>
                        </div>
                        """, unsafe_allow_html=True)
                    
                    st.markdown("<br>", unsafe_allow_html=True)
                    
                    # Download buttons
                    dl_col1, dl_col2 = st.columns(2)
                    
                    with dl_col1:
                        filename, content, mime = create_pdf_download(
                            assessment.assessment_report,
                            f"{assessment.project_name}_v{version_number}"
                        )
                        st.download_button(
                            "📄 Download PDF",
                            content,
                            file_name=filename,
                            mime=mime,
                            key=f"pdf_v{assessment.id}",
                            use_container_width=True
                        )
                    
                    with dl_col2:
                        st.download_button(
                            "📝 Markdown",
                            assessment.assessment_report,
                            file_name=f"{assessment.project_name}_v{version_number}.md",
                            mime="text/markdown",
                            key=f"md_v{assessment.id}",
                            use_container_width=True
                        )
                    
                    # Show report button (toggle view)
                    st.markdown("<br>", unsafe_allow_html=True)
                    if st.button("📖 View Full Report", key=f"view_report_v{assessment.id}", use_container_width=True):
                        st.markdown("---")
                        st.markdown(assessment.assessment_report)
            
            st.markdown("<hr style='margin: 2rem 0; border: none; border-top: 2px solid #e5e7eb;'>", unsafe_allow_html=True)
    
    else:
        # Display assessments in standard list view
        for assessment in filtered_assessments:
            # Use cached risk counts (much faster than parsing report text)
            critical_count = assessment.critical_count or 0
            high_count = assessment.high_count or 0
            medium_count = assessment.medium_count or 0
            
            # Create professional assessment card
            with st.container():
                st.markdown(f"""
                <div style="
                    background: white; 
                padding: 2rem; 
                border-radius: 16px; 
                border: 2px solid #e2e8f0; 
                margin-bottom: 1.5rem;
                box-shadow: 0 2px 8px rgba(0, 0, 0, 0.04);
                transition: all 0.3s ease;
            ">
                <div style="display: flex; justify-content: space-between; align-items: start; margin-bottom: 1rem;">
                    <h3 style="margin: 0; color: #0f172a; font-weight: 700; font-size: 1.5rem;">🔍 {assessment.project_name}</h3>
                    <span class="status-badge" style="background: #d1fae5; color: #065f46; border: 1px solid #a7f3d0; padding: 0.375rem 0.875rem; border-radius: 8px; font-weight: 600; font-size: 0.8rem; text-transform: uppercase;">{assessment.status}</span>
                </div>
                <div style="display: grid; grid-template-columns: repeat(3, 1fr); gap: 1rem; margin: 1rem 0;">
                    <div>
                        <p style="color: #64748b; font-size: 0.85rem; margin: 0; font-weight: 600; text-transform: uppercase; letter-spacing: 0.05em;">Date</p>
                        <p style="color: #0f172a; margin: 0.25rem 0 0 0; font-weight: 600;">{convert_to_sydney_time(assessment.created_at).strftime('%b %d, %Y at %I:%M %p')}</p>
                    </div>
                    <div>
                        <p style="color: #64748b; font-size: 0.85rem; margin: 0; font-weight: 600; text-transform: uppercase; letter-spacing: 0.05em;">Framework</p>
                        <p style="color: #0f172a; margin: 0.25rem 0 0 0; font-weight: 600;">{assessment.framework}</p>
                    </div>
                    <div>
                        <p style="color: #64748b; font-size: 0.85rem; margin: 0; font-weight: 600; text-transform: uppercase; letter-spacing: 0.05em;">Risk Areas</p>
                        <p style="color: #0f172a; margin: 0.25rem 0 0 0; font-weight: 600;">{assessment.risk_type[:30]}...</p>
                    </div>
                </div>
                <div style="display: flex; gap: 1rem; margin-top: 1.5rem; flex-wrap: wrap;">
                    <div style="background: linear-gradient(135deg, #fee2e2 0%, #fecaca 100%); padding: 0.75rem 1.25rem; border-radius: 12px; flex: 1; min-width: 150px; border: 1px solid #fecaca;">
                        <p style="color: #991b1b; font-size: 0.8rem; margin: 0; font-weight: 700; text-transform: uppercase; letter-spacing: 0.05em;">🔴 Critical</p>
                        <p style="color: #991b1b; font-size: 1.75rem; margin: 0.25rem 0 0 0; font-weight: 800;">{critical_count}</p>
                    </div>
                    <div style="background: linear-gradient(135deg, #fed7aa 0%, #fdba74 100%); padding: 0.75rem 1.25rem; border-radius: 12px; flex: 1; min-width: 150px; border: 1px solid #fdba74;">
                        <p style="color: #9a3412; font-size: 0.8rem; margin: 0; font-weight: 700; text-transform: uppercase; letter-spacing: 0.05em;">🟠 High</p>
                        <p style="color: #9a3412; font-size: 1.75rem; margin: 0.25rem 0 0 0; font-weight: 800;">{high_count}</p>
                    </div>
                    <div style="background: linear-gradient(135deg, #fef3c7 0%, #fde68a 100%); padding: 0.75rem 1.25rem; border-radius: 12px; flex: 1; min-width: 150px; border: 1px solid #fde68a;">
                        <p style="color: #92400e; font-size: 0.8rem; margin: 0; font-weight: 700; text-transform: uppercase; letter-spacing: 0.05em;">🟡 Medium</p>
                        <p style="color: #92400e; font-size: 1.75rem; margin: 0.25rem 0 0 0; font-weight: 800;">{medium_count}</p>
                    </div>
                </div>
                </div>
                """, unsafe_allow_html=True)
                
            # Display uploaded documents in standard view
            if assessment.uploaded_files:
                docs_list = assessment.uploaded_files if isinstance(assessment.uploaded_files, list) else []
                if docs_list:
                    st.markdown("**📄 Documents Used:**")
                    st.markdown(" • ".join(docs_list))
                    st.markdown("<br>", unsafe_allow_html=True)
            
            # Download buttons
            col_download1, col_download2, col_spacer = st.columns([1, 1, 2])
            
            with col_download1:
                # PDF Download
                filename, content, mime = create_pdf_download(
                    assessment.assessment_report,
                    assessment.project_name
                )
                st.download_button(
                    "📄 Download PDF",
                    content,
                    file_name=filename,
                    mime=mime,
                    key=f"pdf_{assessment.id}",
                    use_container_width=True
                )
                
                with col_download2:
                    # Markdown Download
                    st.download_button(
                        "📝 Markdown",
                        assessment.assessment_report,
                        file_name=f"{assessment.project_name}_assessment_{assessment.id}.md",
                        mime="text/markdown",
                        key=f"md_{assessment.id}",
                        use_container_width=True
                    )
                
                # View full report in expander
                with st.expander("📖 View Full Report", expanded=False):
                    st.markdown(assessment.assessment_report)
                
                st.markdown("<br>", unsafe_allow_html=True)


def main():
    db = get_db_session()
    try:
        user = load_user(db)
        st.session_state.user = user

        if not user:
            render_login(db)
            return

        render_sidebar(user)
        
        # Enterprise Hero Banner with Enhanced Styling
        st.markdown(
            """
            <div class='hero-banner' style='position: relative; z-index: 1;'>
                <div style='position: relative; z-index: 3; text-align: center;'>
                    <h1 style='text-align: center; margin-bottom: 0.75rem; font-size: 3.5rem;'>🛡️ Enterprise Threat Assessment</h1>
                    <p style='text-align: center; font-size: 1.35rem; opacity: 0.95; margin: 0; font-weight: 500;'>AI-Powered Security Analysis Platform</p>
                    <p style='text-align: center; font-size: 1rem; opacity: 0.85; margin-top: 1rem;'>Comprehensive threat modeling using industry-standard frameworks</p>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

        if user.is_org_admin or user.role == "super_admin":
            tab1, tab2, tab3 = st.tabs(["Threat Modeling", "Past Assessments", "Admin Dashboard"])
            with tab1:
                render_threat_assessment_form(db, user)
            with tab2:
                render_past_assessments(db, user)
            with tab3:
                admin_dashboard.render_admin_dashboard()
        else:
            tab1, tab2 = st.tabs(["Threat Modeling", "Past Assessments"])
            with tab1:
                render_threat_assessment_form(db, user)
            with tab2:
                render_past_assessments(db, user)
    finally:
        db.close()


if __name__ == "__main__":
    main()
