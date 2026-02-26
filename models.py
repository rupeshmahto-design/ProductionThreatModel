"""
Database models for enterprise features
Multi-tenancy, User management, API keys, and Audit logging
"""

from datetime import datetime
from typing import Optional, List
from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Boolean, Text, JSON, Float
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
import hashlib
import secrets

Base = declarative_base()


class Organization(Base):
    """Organization model for multi-tenancy"""
    __tablename__ = 'organizations'
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255), unique=True, nullable=False, index=True)
    slug = Column(String(100), unique=True, nullable=False, index=True)
    domain = Column(String(255))  # For domain-based SSO
    
    # SSO Configuration
    saml_enabled = Column(Boolean, default=False)
    saml_metadata_url = Column(Text)
    saml_entity_id = Column(String(255))
    saml_sso_url = Column(String(512))
    saml_x509_cert = Column(Text)
    
    # Subscription/Limits
    max_users = Column(Integer, default=10)
    max_api_calls_per_month = Column(Integer, default=1000)
    storage_limit_gb = Column(Float, default=10.0)
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    users = relationship("User", back_populates="organization", cascade="all, delete-orphan")
    api_keys = relationship("APIKey", back_populates="organization", cascade="all, delete-orphan")
    audit_logs = relationship("AuditLog", back_populates="organization", cascade="all, delete-orphan")
    threat_assessments = relationship("ThreatAssessment", back_populates="organization", cascade="all, delete-orphan")
    
    def __repr__(self):
        return f"<Organization(id={self.id}, name='{self.name}', slug='{self.slug}')>"


class User(Base):
    """User model with organization isolation"""
    __tablename__ = 'users'
    
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String(255), unique=True, nullable=False, index=True)
    username = Column(String(100), unique=True, nullable=False, index=True)
    full_name = Column(String(255))
    
    # Authentication
    password_hash = Column(String(255))  # For local auth
    saml_name_id = Column(String(255))  # For SAML auth
    
    # Role-based access control
    role = Column(String(50), default='user')  # user, admin, super_admin
    is_active = Column(Boolean, default=True)
    is_org_admin = Column(Boolean, default=False)
    
    # Organization relationship
    organization_id = Column(Integer, ForeignKey('organizations.id'), nullable=False, index=True)
    organization = relationship("Organization", back_populates="users")
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    last_login = Column(DateTime)
    
    # Relationships
    api_keys = relationship("APIKey", back_populates="user", cascade="all, delete-orphan")
    audit_logs = relationship("AuditLog", back_populates="user", cascade="all, delete-orphan")
    threat_assessments = relationship("ThreatAssessment", back_populates="created_by_user", cascade="all, delete-orphan")
    
    def __repr__(self):
        return f"<User(id={self.id}, email='{self.email}', org_id={self.organization_id})>"


class APIKey(Base):
    """API Key model for REST API authentication"""
    __tablename__ = 'api_keys'
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255), nullable=False)  # Descriptive name for the key
    key_prefix = Column(String(20), nullable=False, index=True)  # First 8 chars for display
    key_hash = Column(String(255), nullable=False, unique=True, index=True)  # SHA256 hash
    
    # Permissions
    scopes = Column(JSON)  # ["threat_modeling:read", "threat_modeling:write", "admin:users"]
    rate_limit = Column(Integer, default=100)  # Requests per minute
    
    # Ownership
    organization_id = Column(Integer, ForeignKey('organizations.id'), nullable=False, index=True)
    organization = relationship("Organization", back_populates="api_keys")
    
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False, index=True)
    user = relationship("User", back_populates="api_keys")
    
    # Status
    is_active = Column(Boolean, default=True)
    expires_at = Column(DateTime)
    last_used_at = Column(DateTime)
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    
    # Relationships
    api_usage_logs = relationship("APIUsageLog", back_populates="api_key", cascade="all, delete-orphan")
    
    @staticmethod
    def generate_key():
        """Generate a new API key"""
        key = f"tm_{secrets.token_urlsafe(32)}"
        return key
    
    @staticmethod
    def hash_key(key: str) -> str:
        """Hash an API key for storage"""
        return hashlib.sha256(key.encode()).hexdigest()
    
    def verify_key(self, key: str) -> bool:
        """Verify an API key against the stored hash"""
        return self.key_hash == self.hash_key(key)
    
    def __repr__(self):
        return f"<APIKey(id={self.id}, prefix='{self.key_prefix}', name='{self.name}')>"


class AuditLog(Base):
    """Audit log model for tracking all user actions"""
    __tablename__ = 'audit_logs'
    
    id = Column(Integer, primary_key=True, index=True)
    
    # Who
    user_id = Column(Integer, ForeignKey('users.id'), index=True)
    user = relationship("User", back_populates="audit_logs")
    user_email = Column(String(255))  # Denormalized for reporting
    
    organization_id = Column(Integer, ForeignKey('organizations.id'), nullable=False, index=True)
    organization = relationship("Organization", back_populates="audit_logs")
    
    # What
    action = Column(String(100), nullable=False, index=True)  # e.g., "threat_assessment.create", "user.login"
    resource_type = Column(String(50), index=True)  # e.g., "ThreatAssessment", "User"
    resource_id = Column(Integer)
    
    # Details
    description = Column(Text)
    context_metadata = Column(JSON)  # Additional context (IP, user agent, etc.)
    
    # Result
    status = Column(String(20), default='success')  # success, failure, error
    error_message = Column(Text)
    
    # When
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    
    # Where
    ip_address = Column(String(45))  # IPv6 compatible
    user_agent = Column(String(512))
    
    def __repr__(self):
        return f"<AuditLog(id={self.id}, action='{self.action}', user_id={self.user_id})>"


class APIUsageLog(Base):
    """API usage tracking for rate limiting and analytics"""
    __tablename__ = 'api_usage_logs'
    
    id = Column(Integer, primary_key=True, index=True)
    
    # API Key
    api_key_id = Column(Integer, ForeignKey('api_keys.id'), nullable=False, index=True)
    api_key = relationship("APIKey", back_populates="api_usage_logs")
    
    # Request details
    endpoint = Column(String(255), index=True)
    method = Column(String(10))
    status_code = Column(Integer)
    response_time_ms = Column(Integer)
    
    # Timestamp
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    
    # Request metadata
    ip_address = Column(String(45))
    user_agent = Column(String(512))
    
    def __repr__(self):
        return f"<APIUsageLog(id={self.id}, endpoint='{self.endpoint}', key_id={self.api_key_id})>"


class ThreatAssessment(Base):
    """Threat assessment records for tracking and analytics"""
    __tablename__ = 'threat_assessments'
    
    id = Column(Integer, primary_key=True, index=True)
    
    # Organization and user
    organization_id = Column(Integer, ForeignKey('organizations.id'), nullable=False, index=True)
    organization = relationship("Organization", back_populates="threat_assessments")
    
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False, index=True)
    created_by_user = relationship("User", back_populates="threat_assessments")
    
    # Assessment details
    project_name = Column(String(255), nullable=False)
    project_number = Column(String(100), index=True)  # For grouping assessments by project
    framework = Column(String(200), nullable=False, index=True)  # Support multiple frameworks (e.g., "STRIDE + MITRE ATT&CK")
    risk_type = Column(String(500), index=True)  # Multiple risk areas (e.g., "Supply Chain Risk, Identity & Access Risk, Agentic AI Risk")
    
    # Content
    system_description = Column(Text)
    assessment_report = Column(Text)  # The generated report
    report_html = Column(Text)  # HTML version
    report_meta = Column(JSON)  # Risk scores, counts, etc.
    
    # Risk count cache (computed once, stored for fast retrieval)
    critical_count = Column(Integer, default=0)
    high_count = Column(Integer, default=0)
    medium_count = Column(Integer, default=0)
    
    # Files
    uploaded_files = Column(JSON)  # List of uploaded file names
    
    # Status
    status = Column(String(20), default='completed', index=True)  # draft, in_progress, completed
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def __repr__(self):
        return f"<ThreatAssessment(id={self.id}, project='{self.project_name}', framework='{self.framework}')>"


class UsageStats(Base):
    """Aggregated usage statistics for admin dashboard"""
    __tablename__ = 'usage_stats'
    
    id = Column(Integer, primary_key=True, index=True)
    
    organization_id = Column(Integer, ForeignKey('organizations.id'), nullable=False, index=True)
    
    # Period
    period_start = Column(DateTime, nullable=False, index=True)
    period_end = Column(DateTime, nullable=False)
    period_type = Column(String(20), default='daily')  # daily, weekly, monthly
    
    # Metrics
    total_assessments = Column(Integer, default=0)
    total_api_calls = Column(Integer, default=0)
    total_users = Column(Integer, default=0)
    active_users = Column(Integer, default=0)
    storage_used_gb = Column(Float, default=0.0)
    
    # Breakdown
    assessments_by_framework = Column(JSON)
    assessments_by_risk_type = Column(JSON)
    api_calls_by_endpoint = Column(JSON)
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    
    def __repr__(self):
        return f"<UsageStats(org_id={self.organization_id}, period='{self.period_type}')>"
