"""
Authentication module for SSO (SAML) and session management
"""

from typing import Optional, Dict, Any
from datetime import datetime, timedelta
import secrets
import re

# Input sanitization
try:
    import bleach
    BLEACH_AVAILABLE = True
except ImportError:
    BLEACH_AVAILABLE = False

# Make SAML imports optional (not available on Railway without system dependencies)
try:
    from onelogin.saml2.auth import OneLogin_Saml2_Auth
    from onelogin.saml2.utils import OneLogin_Saml2_Utils
    SAML_AVAILABLE = True
except ImportError:
    SAML_AVAILABLE = False
    OneLogin_Saml2_Auth = None
    OneLogin_Saml2_Utils = None

from sqlalchemy.orm import Session
from models import User, Organization, AuditLog
import jwt
import hashlib
import bcrypt
import os


# ===== PASSWORD HASHING =====

def get_password_hash(password: str) -> str:
    """Hash a password using bcrypt"""
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a password against its hash"""
    return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password.encode('utf-8'))

def create_access_token(data: dict, expires_delta: timedelta = None):
    """Create JWT access token"""
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(hours=24)
    
    to_encode.update({"exp": expire})
    SECRET_KEY = os.getenv("SECRET_KEY", "your-secret-key-here-change-in-production")
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm="HS256")
    return encoded_jwt


class SAMLAuthHandler:
    """Handle SAML SSO authentication"""
    
    def __init__(self, organization: Organization):
        if not SAML_AVAILABLE:
            raise RuntimeError("SAML authentication is not available. Install python3-saml to enable.")
        self.organization = organization
        self.settings = self._build_saml_settings()
    
    def _build_saml_settings(self) -> Dict[str, Any]:
        """Build SAML settings from organization configuration"""
        if not self.organization.saml_enabled:
            raise ValueError(f"SAML not enabled for organization {self.organization.name}")
        
        return {
            "strict": True,
            "debug": False,
            "sp": {
                "entityId": f"https://your-app-domain.com/saml/metadata/{self.organization.slug}",
                "assertionConsumerService": {
                    "url": f"https://your-app-domain.com/saml/acs/{self.organization.slug}",
                    "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
                },
                "singleLogoutService": {
                    "url": f"https://your-app-domain.com/saml/sls/{self.organization.slug}",
                    "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
                },
                "NameIDFormat": "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
                "x509cert": "",
                "privateKey": ""
            },
            "idp": {
                "entityId": self.organization.saml_entity_id,
                "singleSignOnService": {
                    "url": self.organization.saml_sso_url,
                    "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
                },
                "x509cert": self.organization.saml_x509_cert
            }
        }
    
    def prepare_request(self, request_data: Dict[str, Any]) -> Dict[str, Any]:
        """Prepare Flask/Django-like request for python3-saml"""
        return {
            'https': 'on' if request_data.get('https') else 'off',
            'http_host': request_data.get('http_host', 'localhost'),
            'script_name': request_data.get('script_name', ''),
            'server_port': request_data.get('server_port', '443'),
            'get_data': request_data.get('get_data', {}),
            'post_data': request_data.get('post_data', {})
        }
    
    def initiate_login(self, request_data: Dict[str, Any]) -> str:
        """Initiate SAML login and return redirect URL"""
        req = self.prepare_request(request_data)
        auth = OneLogin_Saml2_Auth(req, self.settings)
        return auth.login()
    
    def process_response(self, request_data: Dict[str, Any], db: Session) -> Optional[User]:
        """Process SAML response and return authenticated user"""
        req = self.prepare_request(request_data)
        auth = OneLogin_Saml2_Auth(req, self.settings)
        
        auth.process_response()
        errors = auth.get_errors()
        
        if errors:
            raise Exception(f"SAML authentication failed: {', '.join(errors)}")
        
        if not auth.is_authenticated():
            raise Exception("SAML authentication failed: User not authenticated")
        
        # Get user attributes from SAML response
        attributes = auth.get_attributes()
        name_id = auth.get_nameid()
        
        # Extract user info
        email = attributes.get('email', [name_id])[0] if attributes.get('email') else name_id
        full_name = attributes.get('displayName', [''])[0]
        
        # Find or create user
        user = db.query(User).filter(
            User.saml_name_id == name_id,
            User.organization_id == self.organization.id
        ).first()
        
        if not user:
            # Create new user from SAML
            username = email.split('@')[0]
            user = User(
                email=email,
                username=username,
                full_name=full_name,
                saml_name_id=name_id,
                organization_id=self.organization.id,
                is_active=True
            )
            db.add(user)
        
        # Update last login
        user.last_login = datetime.utcnow()
        
        # Log the login
        audit_log = AuditLog(
            user_id=user.id,
            user_email=user.email,
            organization_id=self.organization.id,
            action="user.login",
            resource_type="User",
            resource_id=user.id,
            description=f"User logged in via SAML SSO",
            status="success",
            ip_address=request_data.get('ip_address'),
            user_agent=request_data.get('user_agent')
        )
        db.add(audit_log)
        
        db.commit()
        db.refresh(user)
        
        return user
    
    def get_logout_url(self, request_data: Dict[str, Any], name_id: str, session_index: str) -> str:
        """Get SAML logout URL"""
        req = self.prepare_request(request_data)
        auth = OneLogin_Saml2_Auth(req, self.settings)
        return auth.logout(name_id=name_id, session_index=session_index)


class SessionManager:
    """Manage user sessions with JWT tokens"""
    
    SECRET_KEY = None  # Should be set from environment variable
    ALGORITHM = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES = 60  # 1 hour
    REFRESH_TOKEN_EXPIRE_DAYS = 7  # 7 days
    
    @classmethod
    def init_secret_key(cls, secret_key: str):
        """Initialize the secret key for JWT"""
        cls.SECRET_KEY = secret_key
    
    @classmethod
    def create_access_token(cls, user: User, expires_delta: Optional[timedelta] = None) -> str:
        """Create JWT access token"""
        if not cls.SECRET_KEY:
            raise ValueError("SECRET_KEY not initialized")
        
        if expires_delta is None:
            expires_delta = timedelta(minutes=cls.ACCESS_TOKEN_EXPIRE_MINUTES)
        
        expire = datetime.utcnow() + expires_delta
        
        payload = {
            "sub": str(user.id),
            "email": user.email,
            "org_id": user.organization_id,
            "role": user.role,
            "is_org_admin": user.is_org_admin,
            "exp": expire,
            "type": "access"
        }
        
        return jwt.encode(payload, cls.SECRET_KEY, algorithm=cls.ALGORITHM)
    
    @classmethod
    def create_refresh_token(cls, user: User) -> str:
        """Create JWT refresh token"""
        if not cls.SECRET_KEY:
            raise ValueError("SECRET_KEY not initialized")
        
        expire = datetime.utcnow() + timedelta(days=cls.REFRESH_TOKEN_EXPIRE_DAYS)
        
        payload = {
            "sub": str(user.id),
            "exp": expire,
            "type": "refresh"
        }
        
        return jwt.encode(payload, cls.SECRET_KEY, algorithm=cls.ALGORITHM)
    
    @classmethod
    def verify_token(cls, token: str) -> Optional[Dict[str, Any]]:
        """Verify and decode JWT token"""
        if not cls.SECRET_KEY:
            raise ValueError("SECRET_KEY not initialized")
        
        try:
            payload = jwt.decode(token, cls.SECRET_KEY, algorithms=[cls.ALGORITHM])
            return payload
        except jwt.ExpiredSignatureError:
            return None
        except jwt.JWTError:
            return None
    
    @classmethod
    def get_user_from_token(cls, token: str, db: Session) -> Optional[User]:
        """Get user from JWT token"""
        payload = cls.verify_token(token)
        if not payload:
            return None
        
        user_id = int(payload.get("sub"))
        user = db.query(User).filter(User.id == user_id, User.is_active == True).first()
        
        return user


class InputValidator:
    """Validate and sanitize user inputs"""
    
    @staticmethod
    def sanitize_text(text: str, max_length: int = 10000) -> str:
        """Sanitize text input to prevent XSS and injection attacks"""
        if not text:
            return ""
        
        # Limit length
        text = text[:max_length]
        
        # Use bleach if available
        if BLEACH_AVAILABLE:
            # Allow only safe HTML tags for markdown content
            allowed_tags = ['p', 'br', 'strong', 'em', 'u', 'h1', 'h2', 'h3', 'h4', 'ul', 'ol', 'li', 'code', 'pre']
            text = bleach.clean(text, tags=allowed_tags, strip=True)
        
        return text.strip()
    
    @staticmethod
    def validate_email(email: str) -> bool:
        """Validate email format"""
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return bool(re.match(pattern, email)) and len(email) <= 255
    
    @staticmethod
    def validate_username(username: str) -> bool:
        """Validate username format (alphanumeric, underscore, hyphen)"""
        pattern = r'^[a-zA-Z0-9_-]{3,50}$'
        return bool(re.match(pattern, username))
    
    @staticmethod
    def sanitize_filename(filename: str) -> str:
        """Sanitize filename to prevent directory traversal"""
        # Remove path separators and null bytes
        filename = filename.replace('/', '').replace('\\', '').replace('\x00', '')
        # Remove leading dots
        filename = filename.lstrip('.')
        # Limit length
        return filename[:255]


class PasswordAuth:
    """Handle password-based authentication (fallback for non-SSO users)"""
    
    @staticmethod
    def hash_password(password: str) -> str:
        """Hash a password using bcrypt (secure, slow by design)"""
        try:
            import bcrypt
            # bcrypt automatically generates salt and handles iterations
            pwd_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt(rounds=12))
            return pwd_hash.decode('utf-8')
        except ImportError:
            # Fallback to SHA256 only if bcrypt not available (NOT RECOMMENDED)
            salt = secrets.token_hex(16)
            pwd_hash = hashlib.sha256((password + salt).encode()).hexdigest()
            return f"sha256${salt}${pwd_hash}"
    
    @staticmethod
    def verify_password(password: str, password_hash: str) -> bool:
        """Verify a password against its hash (supports both bcrypt and legacy SHA256)"""
        try:
            import bcrypt
            # Check if it's a bcrypt hash (starts with $2b$)
            if password_hash.startswith('$2'):
                return bcrypt.checkpw(password.encode('utf-8'), password_hash.encode('utf-8'))
            # Legacy SHA256 support for existing passwords
            elif password_hash.startswith('sha256$'):
                _, salt, pwd_hash = password_hash.split('$')
                computed_hash = hashlib.sha256((password + salt).encode()).hexdigest()
                return computed_hash == pwd_hash
            # Old format without prefix (legacy)
            else:
                salt, pwd_hash = password_hash.split('$')
                computed_hash = hashlib.sha256((password + salt).encode()).hexdigest()
                return computed_hash == pwd_hash
        except Exception:
            return False
    
    @staticmethod
    def authenticate(email: str, password: str, db: Session) -> Optional[User]:
        """Authenticate user with email and password"""
        user = db.query(User).filter(User.email == email, User.is_active == True).first()
        
        if not user or not user.password_hash:
            return None
        
        if not PasswordAuth.verify_password(password, user.password_hash):
            # Log failed login attempt
            audit_log = AuditLog(
                user_id=user.id,
                user_email=user.email,
                organization_id=user.organization_id,
                action="user.login",
                resource_type="User",
                resource_id=user.id,
                description="Failed login attempt (incorrect password)",
                status="failure"
            )
            db.add(audit_log)
            db.commit()
            return None
        
        # Update last login
        user.last_login = datetime.utcnow()
        
        # Log successful login
        audit_log = AuditLog(
            user_id=user.id,
            user_email=user.email,
            organization_id=user.organization_id,
            action="user.login",
            resource_type="User",
            resource_id=user.id,
            description="User logged in successfully",
            status="success"
        )
        db.add(audit_log)
        
        db.commit()
        db.refresh(user)
        
        return user


def require_auth(required_role: Optional[str] = None, require_org_admin: bool = False):
    """Decorator to require authentication and optionally specific role"""
    def decorator(func):
        def wrapper(*args, **kwargs):
            # This would be implemented in the actual API/web framework
            # For FastAPI, use Depends(get_current_user)
            # For Flask, use @login_required
            pass
        return wrapper
    return decorator
