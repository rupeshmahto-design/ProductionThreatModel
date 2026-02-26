# Enterprise Features Guide

## Overview

This guide covers the enterprise-grade features added to the AI-Powered Threat Modeling Tool:

1. **SSO Authentication (SAML 2.0)** - Single Sign-On with your organization's identity provider
2. **REST API** - Programmatic access with API key authentication
3. **Multi-Tenancy** - Organization-level data isolation
4. **Audit Logging** - Complete tracking of all user actions
5. **Admin Dashboard** - User management and usage analytics

---

## 🔐 SSO Authentication (SAML 2.0)

### Configuration

#### Step 1: Enable SAML for Your Organization

1. Sign in as an organization administrator
2. Navigate to **Admin Dashboard** → **Settings** tab
3. Enable SAML SSO and provide:
   - **Identity Provider Entity ID**
   - **SSO URL** (IdP login endpoint)
   - **X.509 Certificate** (from your IdP)

#### Step 2: Configure Your Identity Provider

Your IdP needs the following Service Provider (SP) metadata:

**Metadata URL:**

```
http://your-domain.com/saml/metadata/{org_slug}
```

**Key Endpoints:**

- **ACS (Assertion Consumer Service):** `http://your-domain.com/saml/acs/{org_slug}`
- **SLS (Single Logout Service):** `http://your-domain.com/saml/sls/{org_slug}`
- **Entity ID:** `https://your-app-domain.com/saml/metadata/{org_slug}`

#### Step 3: User Sign-In Flow

Users can sign in via SSO:

1. Go to the application homepage
2. In the sidebar, expand **Enterprise SSO**
3. Enter your organization slug
4. Click **Login with SSO**
5. Complete authentication with your IdP
6. You'll be redirected back and automatically signed in

### Supported Identity Providers

- Okta
- Azure AD / Entra ID
- Google Workspace
- OneLogin
- Auth0
- Any SAML 2.0 compliant IdP

---

## 🔌 REST API

### Authentication

All API requests require an API key passed via the `X-API-Key` header:

```bash
curl -H "X-API-Key: tm_your_api_key_here" \
  http://localhost:8000/api/v1/threat-modeling
```

### Getting an API Key

**Via Admin Dashboard:**

1. Sign in as admin
2. Go to **Admin Dashboard** → **API Keys** tab
3. Click **Create New API Key**
4. Configure name, scopes, and expiration
5. **Save the key immediately** (it won't be shown again)

**Via Database:**

```bash
docker compose exec api python init_db.py --seed
```

### API Endpoints

#### Health Check

```bash
GET /api/health
```

#### Create Threat Assessment

```bash
POST /api/v1/threat-modeling
Content-Type: application/json
X-API-Key: tm_your_api_key

{
  "project_name": "My Web App",
  "system_description": "E-commerce platform with user auth...",
  "framework": "STRIDE",
  "risk_type": "Application Security",
  "company_name": "Acme Corp"
}
```

**Response:**

```json
{
  "assessment_id": 123,
  "project_name": "My Web App",
  "framework": "STRIDE",
  "status": "completed",
  "report": "## Threat Assessment...",
  "created_at": "2026-01-25T10:00:00Z"
}
```

#### Get Threat Assessment

```bash
GET /api/v1/threat-modeling/{assessment_id}
X-API-Key: tm_your_api_key
```

#### List Threat Assessments

```bash
GET /api/v1/threat-modeling?skip=0&limit=20
X-API-Key: tm_your_api_key
```

#### Admin Endpoints (requires admin scope)

**List Users:**

```bash
GET /api/v1/admin/users
X-API-Key: tm_your_admin_key
```

**Get Audit Logs:**

```bash
GET /api/v1/admin/audit-logs?limit=100&action=user.login
X-API-Key: tm_your_admin_key
```

**Get Usage Statistics:**

```bash
GET /api/v1/admin/usage-stats
X-API-Key: tm_your_admin_key
```

### API Scopes

- `threat_modeling:read` - View threat assessments
- `threat_modeling:write` - Create/update threat assessments
- `admin:users` - Manage users
- `admin:audit` - View audit logs
- `admin:stats` - View usage statistics

### Interactive API Docs

Visit `/api/docs` for Swagger UI with interactive testing:

```
http://localhost:8000/api/docs
```

---

## 🏢 Multi-Tenancy

### Organization Isolation

- All data (users, assessments, API keys) is isolated by organization
- Users can only access data within their organization
- API keys are scoped to organizations
- Cross-organization data access is prevented at the database level

### Creating Organizations

Organizations are created via database seeding or directly in the database:

```python
from models import Organization
from database import SessionLocal

db = SessionLocal()
org = Organization(
    name="Acme Corporation",
    slug="acme",
    domain="acme.com",
    max_users=100,
    max_api_calls_per_month=50000
)
db.add(org)
db.commit()
```

---

## 📝 Audit Logging

### What's Logged

Every significant action is recorded with:

- **Who:** User email and ID
- **What:** Action type (e.g., `user.login`, `threat_assessment.create`)
- **When:** Timestamp (UTC)
- **Where:** IP address, user agent
- **Result:** Success, failure, or error
- **Context:** Resource type, resource ID, metadata

### Viewing Audit Logs

**Admin Dashboard:**

1. Go to **Admin Dashboard** → **Audit Logs** tab
2. Filter by time period, action, or status
3. Export to CSV for compliance reporting

**API:**

```bash
GET /api/v1/admin/audit-logs?limit=100
X-API-Key: tm_your_admin_key
```

### Audit Actions

Common actions tracked:

- `user.login` / `user.logout`
- `user.create` / `user.update` / `user.delete`
- `threat_assessment.create` / `threat_assessment.export`
- `api_key.create` / `api_key.revoke`
- `organization.settings_update`
- `sso.login_success` / `sso.login_failure`

### Compliance & Retention

- Audit logs are stored indefinitely by default
- Implement retention policies as needed (e.g., 90 days)
- Export capabilities for SOC 2, ISO 27001, GDPR compliance

---

## ⚙️ Admin Dashboard

### Accessing the Dashboard

1. Sign in with an admin account
2. Click the **Admin Dashboard** tab at the top
3. Or navigate directly to the Admin view in the sidebar

### Features

#### 📊 Overview Tab

- Total users, assessments, API keys
- API usage statistics
- Activity charts (last 30 days)
- Framework distribution
- Recent assessments table

#### 👥 User Management Tab

- View all organization users
- Add new users with initial passwords
- Reset user passwords
- Activate/deactivate users
- Promote users to org admin
- Delete users (with confirmation)

#### 🔑 API Keys Tab

- View all API keys (prefix only, for security)
- Create new API keys with custom scopes
- Set expiration dates
- Revoke/delete API keys
- Track last usage timestamp

#### 📝 Audit Logs Tab

- Filter by time period, action, status
- View detailed event information
- Audit summary statistics
- Export logs to CSV
- Real-time activity monitoring

#### ⚙️ Settings Tab

- Update organization details
- Configure resource limits (users, API calls, storage)
- SAML SSO configuration
- Domain settings

---

## 🚀 Quick Start

### Using Docker (Recommended)

1. **Clone and configure:**

   ```bash
   git clone <your-repo>
   cd enterprise
   cp .env.example .env
   # Edit .env with your ANTHROPIC_API_KEY and JWT_SECRET_KEY
   ```

2. **Start services:**

   ```bash
   docker compose up --build
   ```

3. **Initialize database:**

   ```bash
   docker compose exec api python init_db.py --all
   ```

4. **Access the application:**
   - Web UI: http://localhost:8501
   - API Docs: http://localhost:8000/api/docs
   - Default admin: `admin@example.com` / `admin123`

### Local Development

1. **Install dependencies:**

   ```bash
   pip install -r requirements.txt
   ```

2. **Start PostgreSQL:**

   ```bash
   docker compose up postgres -d
   ```

3. **Initialize database:**

   ```bash
   export DATABASE_URL="postgresql://postgres:postgres@localhost:5432/threat_modeling"
   python init_db.py --all
   ```

4. **Run services:**

   ```bash
   # Terminal 1 - API
   uvicorn api:app --reload --port 8000

   # Terminal 2 - Streamlit
   streamlit run app.py
   ```

---

## 🔒 Security Best Practices

### Production Deployment

1. **Use strong secrets:**

   ```bash
   # Generate secure JWT secret
   python -c "import secrets; print(secrets.token_urlsafe(32))"
   ```

2. **Enable HTTPS:**
   - Set `secure=True` for cookies in production
   - Use a reverse proxy (nginx, Caddy)
   - Configure SSL certificates

3. **Database security:**
   - Use strong PostgreSQL passwords
   - Enable SSL connections
   - Regular backups

4. **Rate limiting:**
   - Configure API rate limits per key
   - Enable Redis-based distributed rate limiting
   - Monitor for abuse

5. **SAML security:**
   - Validate X.509 certificates
   - Enable signature validation
   - Use HTTPS for all SAML endpoints
   - Rotate signing keys regularly

### Environment Variables

Required:

- `ANTHROPIC_API_KEY` - Claude API key
- `DATABASE_URL` - PostgreSQL connection string
- `JWT_SECRET_KEY` - Secret for JWT signing

Optional:

- `REDIS_URL` - Redis for caching/rate limiting
- `FRONTEND_URL` - Streamlit app URL (for SAML redirect)
- `API_RATE_LIMIT_PER_MINUTE` - Global rate limit

---

## 📊 Database Migrations

### Using Alembic

**Generate migration:**

```bash
alembic revision --autogenerate -m "description"
```

**Apply migrations:**

```bash
alembic upgrade head
```

**Rollback:**

```bash
alembic downgrade -1
```

**View history:**

```bash
alembic history
```

### Initial Setup

The `init_db.py` script handles initial table creation. For production:

1. Use Alembic for all schema changes
2. Test migrations in staging first
3. Backup database before migrations
4. Document breaking changes

---

## 🧪 Testing

### API Testing

Use the interactive docs or curl:

```bash
# Health check
curl http://localhost:8000/api/health

# Create assessment
curl -X POST http://localhost:8000/api/v1/threat-modeling \
  -H "Content-Type: application/json" \
  -H "X-API-Key: tm_your_key" \
  -d '{
    "project_name": "Test Project",
    "system_description": "Test system",
    "framework": "STRIDE"
  }'
```

### Manual Testing Checklist

- [ ] User sign-in (password)
- [ ] User sign-in (SSO)
- [ ] Create threat assessment
- [ ] View threat assessment
- [ ] Export to PDF
- [ ] Create API key
- [ ] Use API to create assessment
- [ ] View audit logs
- [ ] User management (add/remove)
- [ ] Organization settings update

---

## 🆘 Troubleshooting

### SAML Issues

**Error: "SAML not enabled"**

- Check organization settings in Admin Dashboard
- Verify SAML configuration is complete

**Error: "Invalid signature"**

- Verify X.509 certificate is correct
- Check that certificate hasn't expired
- Ensure certificate format is PEM

**Redirect loop:**

- Check FRONTEND_URL environment variable
- Verify ACS URL in IdP matches your configuration

### Database Issues

**Connection refused:**

- Ensure PostgreSQL is running: `docker compose ps`
- Check DATABASE_URL is correct
- Verify network connectivity

**Migration conflicts:**

- Run `alembic history` to check state
- Use `alembic stamp head` to reset (⚠️ careful)
- Manually resolve conflicts in versions/

### API Issues

**401 Unauthorized:**

- Verify API key is correct
- Check key hasn't expired
- Ensure key is active

**403 Forbidden:**

- Check API key has required scopes
- Verify user has necessary permissions

---

## 📚 Additional Resources

- [FastAPI Documentation](https://fastapi.tiangolo.com/)
- [python3-saml Documentation](https://github.com/SAML-Toolkits/python3-saml)
- [SQLAlchemy Documentation](https://docs.sqlalchemy.org/)
- [Streamlit Documentation](https://docs.streamlit.io/)

---

## 🤝 Support

For enterprise support:

- File issues on GitHub
- Contact your organization administrator
- Review audit logs for debugging

---

## 📄 License

MIT License - See LICENSE file for details
