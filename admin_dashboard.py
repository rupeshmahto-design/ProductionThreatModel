"""
Admin Dashboard for User Management and Usage Analytics
Streamlit pages for organization administrators
"""

import streamlit as st
import pandas as pd
from datetime import datetime, timedelta
from typing import Optional
from sqlalchemy.orm import Session
import plotly.express as px
import plotly.graph_objects as go

from models import User, Organization, APIKey, AuditLog, ThreatAssessment, UsageStats, APIUsageLog
from sqlalchemy import func
from database import SessionLocal, get_db
from auth import PasswordAuth, SessionManager
from audit import AuditLogger, AuditActions, get_audit_summary


def check_admin_access(user: User) -> bool:
    """Check if user has admin access"""
    return user.is_org_admin or user.role == "super_admin"


def render_admin_dashboard():
    """Main admin dashboard page"""
    st.title("🔧 Admin Dashboard")
    
    # Check if user is logged in and is admin
    if 'user' not in st.session_state or not st.session_state.user:
        st.error("Please log in to access the admin dashboard")
        return
    
    user = st.session_state.user
    if not check_admin_access(user):
        st.error("⛔ Access Denied: Admin privileges required")
        return
    
    # Get database session
    db = SessionLocal()
    
    try:
        nav_items = {
            "📊 Overview": render_overview_tab,
            "👥 User Management": render_user_management_tab,
            "📝 Audit Logs": render_audit_logs_tab,
            "🔑 API Keys": render_api_keys_tab,
            "📈 Usage Statistics": render_usage_stats_tab,
            "🩺 System Health": render_system_health_tab,
            "⚙️ Settings": render_settings_tab,
        }

        col_nav, col_main = st.columns([1, 3])
        with col_nav:
            st.markdown("### Navigation")
            choice = st.radio("Select a section", list(nav_items.keys()), index=0)

        with col_main:
            nav_items[choice](db, user)
    
    finally:
        db.close()


def render_overview_tab(db: Session, user: User):
    """Render overview/analytics tab"""
    st.header("Organization Overview")
    
    # Get organization
    org = db.query(Organization).filter(Organization.id == user.organization_id).first()
    
    # Key metrics
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        total_users = db.query(User).filter(User.organization_id == user.organization_id).count()
        st.metric("Total Users", total_users, delta=f"Max: {org.max_users}")
    
    with col2:
        total_assessments = db.query(ThreatAssessment).filter(
            ThreatAssessment.organization_id == user.organization_id
        ).count()
        st.metric("Total Assessments", total_assessments)
    
    with col3:
        active_api_keys = db.query(APIKey).filter(
            APIKey.organization_id == user.organization_id,
            APIKey.is_active == True
        ).count()
        st.metric("Active API Keys", active_api_keys)
    
    with col4:
        # API calls this month
        first_day_of_month = datetime.now().replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        api_calls_this_month = db.query(APIUsageLog).join(APIKey).filter(
            APIKey.organization_id == user.organization_id,
            APIUsageLog.timestamp >= first_day_of_month
        ).count()
        st.metric(
            "API Calls This Month", 
            api_calls_this_month,
            delta=f"Limit: {org.max_api_calls_per_month}"
        )
    
    st.markdown("---")
    
    # Recent activity chart
    st.subheader("📈 Activity Over Time")
    
    # Get assessments over last 30 days
    thirty_days_ago = datetime.now() - timedelta(days=30)
    assessments = db.query(ThreatAssessment).filter(
        ThreatAssessment.organization_id == user.organization_id,
        ThreatAssessment.created_at >= thirty_days_ago
    ).all()
    
    if assessments:
        df = pd.DataFrame([
            {"Date": a.created_at.date(), "Framework": a.framework}
            for a in assessments
        ])
        
        # Group by date
        daily_counts = df.groupby("Date").size().reset_index(name="Count")
        
        fig = px.line(
            daily_counts,
            x="Date",
            y="Count",
            title="Threat Assessments (Last 30 Days)",
            markers=True
        )
        fig.update_layout(
            xaxis_title="Date",
            yaxis_title="Number of Assessments",
            hovermode='x unified'
        )
        st.plotly_chart(fig, use_container_width=True)
        
        # Framework breakdown
        col1, col2 = st.columns(2)
        
        with col1:
            framework_counts = df["Framework"].value_counts()
            fig = px.pie(
                values=framework_counts.values,
                names=framework_counts.index,
                title="Assessments by Framework"
            )
            st.plotly_chart(fig, use_container_width=True)
        
        with col2:
            # Recent assessments table
            st.subheader("Recent Assessments")
            recent = df.sort_values("Date", ascending=False).head(10)
            st.dataframe(recent, use_container_width=True)
    else:
        st.info("No assessment data available yet")


def render_user_management_tab(db: Session, admin_user: User):
    """Render user management tab"""
    st.header("👥 User Management")
    
    # Get all users in organization
    users = db.query(User).filter(
        User.organization_id == admin_user.organization_id
    ).all()
    
    # Add new user section
    with st.expander("➕ Add New User", expanded=False):
        with st.form("add_user_form"):
            col1, col2 = st.columns(2)
            
            with col1:
                new_email = st.text_input("Email")
                new_username = st.text_input("Username")
            
            with col2:
                new_full_name = st.text_input("Full Name")
                new_role = st.selectbox("Role", ["user", "admin"])
            
            new_password = st.text_input("Initial Password", type="password")
            is_org_admin = st.checkbox("Organization Admin")
            
            if st.form_submit_button("Add User"):
                if new_email and new_username and new_password:
                    # Check if user already exists
                    existing = db.query(User).filter(
                        (User.email == new_email) | (User.username == new_username)
                    ).first()
                    
                    if existing:
                        st.error("User with this email or username already exists")
                    else:
                        # Create new user
                        new_user = User(
                            email=new_email,
                            username=new_username,
                            full_name=new_full_name,
                            password_hash=PasswordAuth.hash_password(new_password),
                            role=new_role,
                            is_org_admin=is_org_admin,
                            organization_id=admin_user.organization_id,
                            is_active=True
                        )
                        db.add(new_user)
                        
                        # Log the action
                        AuditLogger.log_user_action(
                            db=db,
                            user=admin_user,
                            action=AuditActions.USER_CREATE,
                            resource_type="User",
                            resource_id=new_user.id,
                            description=f"Created new user: {new_email}"
                        )
                        
                        db.commit()
                        st.success(f"✅ User {new_email} created successfully!")
                        st.rerun()
                else:
                    st.error("Please fill in all required fields")
    
    st.markdown("---")
    
    # Display users table
    st.subheader("Current Users")
    
    if users:
        # Create DataFrame for display
        users_data = []
        for u in users:
            users_data.append({
                "ID": u.id,
                "Email": u.email,
                "Username": u.username,
                "Full Name": u.full_name or "-",
                "Role": u.role,
                "Org Admin": "✅" if u.is_org_admin else "❌",
                "Active": "✅" if u.is_active else "❌",
                "Last Login": u.last_login.strftime("%Y-%m-%d %H:%M") if u.last_login else "Never",
                "Created": u.created_at.strftime("%Y-%m-%d")
            })
        
        df = pd.DataFrame(users_data)
        st.dataframe(df, use_container_width=True, hide_index=True)
        
        # User actions
        st.subheader("User Actions")
        selected_user_id = st.selectbox(
            "Select User",
            options=[u.id for u in users],
            format_func=lambda x: next(u.email for u in users if u.id == x)
        )
        
        if selected_user_id:
            selected_user = next(u for u in users if u.id == selected_user_id)
            
            col1, col2, col3 = st.columns(3)
            
            with col1:
                if st.button("🔄 Reset Password"):
                    # Show password reset form
                    st.session_state.show_password_reset = selected_user_id
            
            with col2:
                if selected_user.is_active:
                    if st.button("🚫 Deactivate User"):
                        selected_user.is_active = False
                        AuditLogger.log_user_action(
                            db=db,
                            user=admin_user,
                            action=AuditActions.USER_UPDATE,
                            resource_type="User",
                            resource_id=selected_user.id,
                            description=f"Deactivated user: {selected_user.email}"
                        )
                        db.commit()
                        st.success("User deactivated")
                        st.rerun()
                else:
                    if st.button("✅ Activate User"):
                        selected_user.is_active = True
                        AuditLogger.log_user_action(
                            db=db,
                            user=admin_user,
                            action=AuditActions.USER_UPDATE,
                            resource_type="User",
                            resource_id=selected_user.id,
                            description=f"Activated user: {selected_user.email}"
                        )
                        db.commit()
                        st.success("User activated")
                        st.rerun()
            
            with col3:
                if st.button("🗑️ Delete User"):
                    # Confirm deletion
                    st.session_state.confirm_delete_user = selected_user_id
    else:
        st.info("No users found")


def render_api_keys_tab(db: Session, user: User):
    """Render API keys management tab"""
    st.header("🔑 API Key Management")
    
    # Get all API keys for organization
    api_keys = db.query(APIKey).filter(
        APIKey.organization_id == user.organization_id
    ).all()
    
    # Create new API key
    with st.expander("➕ Create New API Key", expanded=False):
        with st.form("create_api_key_form"):
            key_name = st.text_input("Key Name", help="Descriptive name for the API key")
            
            scopes = st.multiselect(
                "Scopes",
                options=[
                    "threat_modeling:read",
                    "threat_modeling:write",
                    "admin:users",
                    "admin:audit",
                    "admin:stats"
                ],
                default=["threat_modeling:read", "threat_modeling:write"]
            )
            
            expires_in_days = st.number_input(
                "Expires in (days)",
                min_value=1,
                max_value=365,
                value=90,
                help="Leave empty for no expiration"
            )
            
            if st.form_submit_button("Create API Key"):
                if key_name:
                    # Generate API key
                    api_key = APIKey.generate_key()
                    key_hash = APIKey.hash_key(api_key)
                    key_prefix = api_key[:12]  # First 12 chars for display
                    
                    expires_at = None
                    if expires_in_days:
                        expires_at = datetime.utcnow() + timedelta(days=expires_in_days)
                    
                    # Create API key record
                    new_key = APIKey(
                        name=key_name,
                        key_prefix=key_prefix,
                        key_hash=key_hash,
                        scopes=scopes,
                        organization_id=user.organization_id,
                        user_id=user.id,
                        is_active=True,
                        expires_at=expires_at
                    )
                    db.add(new_key)
                    
                    # Log the action
                    AuditLogger.log_user_action(
                        db=db,
                        user=user,
                        action=AuditActions.API_KEY_CREATE,
                        resource_type="APIKey",
                        resource_id=new_key.id,
                        description=f"Created API key: {key_name}"
                    )
                    
                    db.commit()
                    
                    # Display the API key (only time it's shown)
                    st.success("✅ API Key created successfully!")
                    st.code(api_key, language="text")
                    st.warning("⚠️ **Save this key now!** You won't be able to see it again.")
                    
                    st.rerun()
                else:
                    st.error("Please provide a name for the API key")
    
    st.markdown("---")
    
    # Display API keys table
    st.subheader("Existing API Keys")
    
    if api_keys:
        keys_data = []
        for key in api_keys:
            keys_data.append({
                "ID": key.id,
                "Name": key.name,
                "Prefix": key.key_prefix,
                "Scopes": ", ".join(key.scopes) if key.scopes else "-",
                "Status": "🟢 Active" if key.is_active else "🔴 Inactive",
                "Last Used": key.last_used_at.strftime("%Y-%m-%d %H:%M") if key.last_used_at else "Never",
                "Expires": key.expires_at.strftime("%Y-%m-%d") if key.expires_at else "Never",
                "Created": key.created_at.strftime("%Y-%m-%d")
            })
        
        df = pd.DataFrame(keys_data)
        st.dataframe(df, use_container_width=True, hide_index=True)
        
        # API key actions
        st.subheader("API Key Actions")
        selected_key_id = st.selectbox(
            "Select API Key",
            options=[k.id for k in api_keys],
            format_func=lambda x: next(k.name for k in api_keys if k.id == x)
        )
        
        if selected_key_id:
            selected_key = next(k for k in api_keys if k.id == selected_key_id)
            
            col1, col2 = st.columns(2)
            
            with col1:
                if selected_key.is_active:
                    if st.button("🚫 Revoke Key"):
                        selected_key.is_active = False
                        AuditLogger.log_user_action(
                            db=db,
                            user=user,
                            action=AuditActions.API_KEY_REVOKE,
                            resource_type="APIKey",
                            resource_id=selected_key.id,
                            description=f"Revoked API key: {selected_key.name}"
                        )
                        db.commit()
                        st.success("API key revoked")
                        st.rerun()
            
            with col2:
                if st.button("🗑️ Delete Key"):
                    db.delete(selected_key)
                    AuditLogger.log_user_action(
                        db=db,
                        user=user,
                        action=AuditActions.API_KEY_DELETE,
                        resource_type="APIKey",
                        resource_id=selected_key.id,
                        description=f"Deleted API key: {selected_key.name}"
                    )
                    db.commit()
                    st.success("API key deleted")
                    st.rerun()
    else:
        st.info("No API keys found")


def render_audit_logs_tab(db: Session, user: User):
    """Render audit logs tab"""
    st.header("📝 Audit Logs")
    
    # Filters
    col1, col2, col3 = st.columns(3)
    
    with col1:
        days_back = st.selectbox("Time Period", [1, 7, 30, 90], index=2, format_func=lambda x: f"Last {x} days")
    
    with col2:
        action_filter = st.selectbox("Action", ["All"] + [
            "user.login",
            "user.create",
            "threat_assessment.create",
            "api_key.create"
        ])
    
    with col3:
        status_filter = st.selectbox("Status", ["All", "success", "failure", "error"])
    
    # Build query
    start_date = datetime.now() - timedelta(days=days_back)
    query = db.query(AuditLog).filter(
        AuditLog.organization_id == user.organization_id,
        AuditLog.timestamp >= start_date
    )
    
    if action_filter != "All":
        query = query.filter(AuditLog.action == action_filter)
    
    if status_filter != "All":
        query = query.filter(AuditLog.status == status_filter)
    
    logs = query.order_by(AuditLog.timestamp.desc()).limit(100).all()
    
    # Display summary statistics
    summary = get_audit_summary(
        db=db,
        organization_id=user.organization_id,
        start_date=start_date
    )
    
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric("Total Events", summary["total_events"])
    
    with col2:
        st.metric("Success Rate", f"{summary['success_rate']}%")
    
    with col3:
        st.metric("Unique Users", len(summary["users_breakdown"]))
    
    with col4:
        st.metric("Action Types", len(summary["actions_breakdown"]))
    
    st.markdown("---")


def render_usage_stats_tab(db: Session, user: User):
    """Render usage statistics computed from APIUsageLog joined with APIKey."""
    st.header("Usage Statistics")

    # Aggregates for the organization
    total_requests = (
        db.query(APIUsageLog)
        .join(APIKey, APIUsageLog.api_key_id == APIKey.id)
        .filter(APIKey.organization_id == user.organization_id)
        .count()
    )

    avg_latency = (
        db.query(func.avg(APIUsageLog.response_time_ms))
        .join(APIKey, APIUsageLog.api_key_id == APIKey.id)
        .filter(APIKey.organization_id == user.organization_id)
        .scalar() or 0
    )

    error_count = (
        db.query(APIUsageLog)
        .join(APIKey, APIUsageLog.api_key_id == APIKey.id)
        .filter(APIKey.organization_id == user.organization_id, APIUsageLog.status_code >= 400)
        .count()
    )
    error_rate = (error_count / total_requests * 100) if total_requests else 0

    active_keys = db.query(APIKey).filter(APIKey.organization_id == user.organization_id, APIKey.is_active == True).count()

    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Total Requests", f"{total_requests:,}")
    col2.metric("Avg Latency (ms)", f"{avg_latency:.1f}")
    col3.metric("Error Rate", f"{error_rate:.2f}%")
    col4.metric("Active API Keys", active_keys)

    # API usage breakdown (recent logs)
    recent_logs = (
        db.query(APIUsageLog, APIKey)
        .join(APIKey, APIUsageLog.api_key_id == APIKey.id)
        .filter(APIKey.organization_id == user.organization_id)
        .order_by(APIUsageLog.timestamp.desc())
        .limit(200)
        .all()
    )

    if recent_logs:
        df = pd.DataFrame([
            {
                "timestamp": log.timestamp,
                "api_key_prefix": key.key_prefix,
                "endpoint": log.endpoint,
                "method": log.method,
                "latency_ms": log.response_time_ms,
                "status": log.status_code,
            }
            for (log, key) in recent_logs
        ])

        st.markdown("### Recent API Usage")
        st.dataframe(df, use_container_width=True, height=400)
    else:
        st.info("No API usage logs available yet.")


def render_system_health_tab(db: Session, user: User):
    """Render simple system health/status checks"""
    st.header("System Health")

    # Basic health checks
    total_users = db.query(User).filter(User.organization_id == user.organization_id).count()
    total_assessments = db.query(ThreatAssessment).filter(ThreatAssessment.organization_id == user.organization_id).count()
    active_api_keys = db.query(APIKey).filter(APIKey.organization_id == user.organization_id, APIKey.is_active == True).count()

    col1, col2, col3 = st.columns(3)
    col1.metric("Users", total_users)
    col2.metric("Threat Assessments", total_assessments)
    col3.metric("Active API Keys", active_api_keys)

    st.markdown("### Service Status")
    st.success("Database: Connected")
    st.info("App: Running (Streamlit)")
    st.info("API: Use docker-compose api service or run uvicorn")

    st.markdown("### Maintenance")
    st.caption("Ensure Alembic migrations are up-to-date; check CI pipeline for latest build status.")
    
    # Display logs
    if logs:
        logs_data = []
        for log in logs:
            logs_data.append({
                "Timestamp": log.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                "User": log.user_email or "System",
                "Action": log.action,
                "Resource": f"{log.resource_type} #{log.resource_id}" if log.resource_type else "-",
                "Status": "✅" if log.status == "success" else "❌" if log.status == "error" else "⚠️",
                "Description": log.description or "-",
                "IP": log.ip_address or "-"
            })
        
        df = pd.DataFrame(logs_data)
        st.dataframe(df, use_container_width=True, hide_index=True, height=400)
        
        # Export option
        if st.button("📥 Export Audit Logs"):
            csv = df.to_csv(index=False)
            st.download_button(
                label="Download CSV",
                data=csv,
                file_name=f"audit_logs_{datetime.now().strftime('%Y%m%d')}.csv",
                mime="text/csv"
            )
    else:
        st.info("No audit logs found for the selected filters")


def render_settings_tab(db: Session, user: User):
    """Render organization settings tab"""
    st.header("⚙️ Organization Settings")
    
    # Get organization
    org = db.query(Organization).filter(Organization.id == user.organization_id).first()
    
    # Organization details
    st.subheader("Organization Details")
    
    with st.form("org_settings_form"):
        org_name = st.text_input("Organization Name", value=org.name)
        org_domain = st.text_input("Domain", value=org.domain or "")
        
        col1, col2 = st.columns(2)
        
        with col1:
            max_users = st.number_input("Max Users", min_value=1, value=org.max_users)
            max_api_calls = st.number_input(
                "Max API Calls/Month",
                min_value=100,
                value=org.max_api_calls_per_month
            )
        
        with col2:
            storage_limit = st.number_input(
                "Storage Limit (GB)",
                min_value=1.0,
                value=float(org.storage_limit_gb)
            )
        
        if st.form_submit_button("💾 Save Settings"):
            org.name = org_name
            org.domain = org_domain
            org.max_users = max_users
            org.max_api_calls_per_month = max_api_calls
            org.storage_limit_gb = storage_limit
            
            AuditLogger.log_user_action(
                db=db,
                user=user,
                action=AuditActions.ORG_SETTINGS_UPDATE,
                resource_type="Organization",
                resource_id=org.id,
                description="Updated organization settings"
            )
            
            db.commit()
            st.success("✅ Settings saved successfully!")
    
    st.markdown("---")
    
    # SSO Configuration
    st.subheader("🔐 SSO Configuration (SAML)")
    
    with st.form("sso_config_form"):
        saml_enabled = st.checkbox("Enable SAML SSO", value=org.saml_enabled)
        
        if saml_enabled:
            saml_entity_id = st.text_input(
                "Identity Provider Entity ID",
                value=org.saml_entity_id or ""
            )
            saml_sso_url = st.text_input(
                "SSO URL",
                value=org.saml_sso_url or ""
            )
            saml_x509_cert = st.text_area(
                "X.509 Certificate",
                value=org.saml_x509_cert or "",
                height=200,
                help="Paste the X.509 certificate from your identity provider"
            )
        
        if st.form_submit_button("💾 Save SSO Settings"):
            org.saml_enabled = saml_enabled
            if saml_enabled:
                org.saml_entity_id = saml_entity_id
                org.saml_sso_url = saml_sso_url
                org.saml_x509_cert = saml_x509_cert
            
            AuditLogger.log_user_action(
                db=db,
                user=user,
                action=AuditActions.SSO_CONFIG_UPDATE,
                resource_type="Organization",
                resource_id=org.id,
                description="Updated SSO configuration"
            )
            
            db.commit()
            st.success("✅ SSO settings saved successfully!")


if __name__ == "__main__":
    render_admin_dashboard()
