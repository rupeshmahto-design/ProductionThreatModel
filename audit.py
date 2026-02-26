"""
Audit logging utilities for tracking user actions
"""

from typing import Optional, Dict, Any
from datetime import datetime
from sqlalchemy.orm import Session
from models import AuditLog, User, Organization
from functools import wraps
import inspect


class AuditLogger:
    """Centralized audit logging utility"""
    
    @staticmethod
    def log(
        db: Session,
        user: Optional[User],
        organization_id: int,
        action: str,
        resource_type: Optional[str] = None,
        resource_id: Optional[int] = None,
        description: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        status: str = "success",
        error_message: Optional[str] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None
    ) -> AuditLog:
        """
        Create an audit log entry
        
        Args:
            db: Database session
            user: User performing the action (can be None for system actions)
            organization_id: Organization ID
            action: Action being performed (e.g., "user.login", "assessment.create")
            resource_type: Type of resource being acted upon
            resource_id: ID of the resource
            description: Human-readable description
            metadata: Additional context as JSON
            status: "success", "failure", or "error"
            error_message: Error message if status is "error"
            ip_address: IP address of the requester
            user_agent: User agent string
        
        Returns:
            AuditLog: The created audit log entry
        """
        audit_log = AuditLog(
            user_id=user.id if user else None,
            user_email=user.email if user else None,
            organization_id=organization_id,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            description=description,
            metadata=metadata,
            status=status,
            error_message=error_message,
            ip_address=ip_address,
            user_agent=user_agent
        )
        
        db.add(audit_log)
        db.commit()
        db.refresh(audit_log)
        
        return audit_log
    
    @staticmethod
    def log_user_action(
        db: Session,
        user: User,
        action: str,
        description: str,
        **kwargs
    ) -> AuditLog:
        """Convenience method for logging user actions"""
        return AuditLogger.log(
            db=db,
            user=user,
            organization_id=user.organization_id,
            action=action,
            description=description,
            **kwargs
        )
    
    @staticmethod
    def log_system_action(
        db: Session,
        organization_id: int,
        action: str,
        description: str,
        **kwargs
    ) -> AuditLog:
        """Convenience method for logging system actions"""
        return AuditLogger.log(
            db=db,
            user=None,
            organization_id=organization_id,
            action=action,
            description=description,
            **kwargs
        )


def audit_action(action: str, resource_type: Optional[str] = None):
    """
    Decorator to automatically log function calls as audit events
    
    Usage:
        @audit_action("user.update", resource_type="User")
        def update_user(db: Session, user: User, user_id: int, updates: dict):
            # Function implementation
            pass
    
    The decorator expects the decorated function to have:
    - db: Session parameter
    - user: User parameter (or None for system actions)
    - Returns: The created/updated resource (with an 'id' attribute)
    """
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            # Get function signature
            sig = inspect.signature(func)
            bound_args = sig.bind(*args, **kwargs)
            bound_args.apply_defaults()
            
            # Extract required parameters
            db = bound_args.arguments.get('db')
            user = bound_args.arguments.get('user')
            
            if not db:
                raise ValueError("audit_action decorator requires 'db: Session' parameter")
            
            try:
                # Execute the function
                result = func(*args, **kwargs)
                
                # Determine resource_id
                resource_id = None
                if result and hasattr(result, 'id'):
                    resource_id = result.id
                elif 'id' in bound_args.arguments:
                    resource_id = bound_args.arguments['id']
                elif resource_type and resource_type.lower() + '_id' in bound_args.arguments:
                    resource_id = bound_args.arguments[resource_type.lower() + '_id']
                
                # Log successful action
                description = f"Executed {func.__name__}"
                
                if user:
                    AuditLogger.log_user_action(
                        db=db,
                        user=user,
                        action=action,
                        resource_type=resource_type,
                        resource_id=resource_id,
                        description=description,
                        status="success"
                    )
                else:
                    # System action
                    org_id = bound_args.arguments.get('organization_id', 1)
                    AuditLogger.log_system_action(
                        db=db,
                        organization_id=org_id,
                        action=action,
                        resource_type=resource_type,
                        resource_id=resource_id,
                        description=description,
                        status="success"
                    )
                
                return result
                
            except Exception as e:
                # Log failed action
                if user:
                    AuditLogger.log_user_action(
                        db=db,
                        user=user,
                        action=action,
                        resource_type=resource_type,
                        description=f"Failed to execute {func.__name__}",
                        status="error",
                        error_message=str(e)
                    )
                
                # Re-raise the exception
                raise
        
        return wrapper
    return decorator


# Common audit action constants
class AuditActions:
    """Standard audit action names"""
    
    # User actions
    USER_LOGIN = "user.login"
    USER_LOGOUT = "user.logout"
    USER_CREATE = "user.create"
    USER_UPDATE = "user.update"
    USER_DELETE = "user.delete"
    USER_PASSWORD_CHANGE = "user.password_change"
    
    # Organization actions
    ORG_CREATE = "organization.create"
    ORG_UPDATE = "organization.update"
    ORG_DELETE = "organization.delete"
    ORG_SETTINGS_UPDATE = "organization.settings_update"
    
    # API Key actions
    API_KEY_CREATE = "api_key.create"
    API_KEY_DELETE = "api_key.delete"
    API_KEY_REVOKE = "api_key.revoke"
    
    # Threat Assessment actions
    ASSESSMENT_CREATE = "threat_assessment.create"
    ASSESSMENT_UPDATE = "threat_assessment.update"
    ASSESSMENT_DELETE = "threat_assessment.delete"
    ASSESSMENT_EXPORT = "threat_assessment.export"
    
    # Admin actions
    ADMIN_USER_INVITE = "admin.user_invite"
    ADMIN_USER_REMOVE = "admin.user_remove"
    ADMIN_ROLE_CHANGE = "admin.role_change"
    
    # SSO actions
    SSO_CONFIG_UPDATE = "sso.config_update"
    SSO_LOGIN_ATTEMPT = "sso.login_attempt"
    SSO_LOGIN_SUCCESS = "sso.login_success"
    SSO_LOGIN_FAILURE = "sso.login_failure"


def get_audit_summary(
    db: Session,
    organization_id: int,
    start_date: Optional[datetime] = None,
    end_date: Optional[datetime] = None,
    user_id: Optional[int] = None,
    action: Optional[str] = None
) -> Dict[str, Any]:
    """
    Generate audit summary statistics
    
    Returns:
        Dict with summary statistics including:
        - total_events: Total number of audit events
        - success_rate: Percentage of successful actions
        - actions_breakdown: Count of each action type
        - users_breakdown: Count of actions per user
        - timeline: Events grouped by time period
    """
    query = db.query(AuditLog).filter(AuditLog.organization_id == organization_id)
    
    if start_date:
        query = query.filter(AuditLog.timestamp >= start_date)
    if end_date:
        query = query.filter(AuditLog.timestamp <= end_date)
    if user_id:
        query = query.filter(AuditLog.user_id == user_id)
    if action:
        query = query.filter(AuditLog.action == action)
    
    logs = query.all()
    
    if not logs:
        return {
            "total_events": 0,
            "success_rate": 0.0,
            "actions_breakdown": {},
            "users_breakdown": {},
            "status_breakdown": {}
        }
    
    # Calculate statistics
    total_events = len(logs)
    success_count = sum(1 for log in logs if log.status == "success")
    success_rate = (success_count / total_events) * 100 if total_events > 0 else 0
    
    # Actions breakdown
    actions_breakdown = {}
    for log in logs:
        actions_breakdown[log.action] = actions_breakdown.get(log.action, 0) + 1
    
    # Users breakdown
    users_breakdown = {}
    for log in logs:
        if log.user_email:
            users_breakdown[log.user_email] = users_breakdown.get(log.user_email, 0) + 1
    
    # Status breakdown
    status_breakdown = {}
    for log in logs:
        status_breakdown[log.status] = status_breakdown.get(log.status, 0) + 1
    
    return {
        "total_events": total_events,
        "success_rate": round(success_rate, 2),
        "actions_breakdown": actions_breakdown,
        "users_breakdown": users_breakdown,
        "status_breakdown": status_breakdown,
        "date_range": {
            "start": start_date.isoformat() if start_date else None,
            "end": end_date.isoformat() if end_date else None
        }
    }
