# 🔒 AI-Powered Threat Modeling Tool - Enterprise Edition

Enterprise-grade threat assessment platform with SSO, API access, multi-tenancy, audit logging, and admin controls.

![Version](https://img.shields.io/badge/version-2.0.0-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Python](https://img.shields.io/badge/python-3.11+-blue)
![Enterprise](https://img.shields.io/badge/enterprise-ready-success)

---

## ✨ Enterprise Features

### 🔐 **SSO Authentication (SAML 2.0)**

- Single Sign-On with any SAML 2.0 IdP (Okta, Azure AD, Google Workspace)
- Automatic user provisioning
- Single Logout (SLO) support
- Signed metadata generation

### 🔌 **REST API**

- Full programmatic access
- API key authentication with scoped permissions
- Rate limiting per key
- OpenAPI/Swagger documentation
- Comprehensive endpoints for all operations

### 🏢 **Multi-Tenancy**

- Complete organization-level data isolation
- Per-org resource limits (users, API calls, storage)
- Domain-based SSO configuration
- Separate billing and usage tracking

### 📝 **Audit Logging**

- Complete activity tracking (who, what, when, where)
- Compliance-ready logs (SOC 2, ISO 27001, GDPR)
- Filterable by time, action, user, status
- CSV export for reporting
- Real-time monitoring

### ⚙️ **Admin Dashboard**

- User management (invite, activate, deactivate, roles)
- API key lifecycle management
- Usage analytics and charts
- Audit log viewer
- Organization settings and SSO configuration

---

## 🚀 Quick Start (Docker)

### Prerequisites

- Docker & Docker Compose
- Anthropic API key ([get one here](https://console.anthropic.com/))

### 1. Clone & Configure

```bash
git clone <your-repo>
cd enterprise

# Copy and edit environment variables
cp .env.example .env
# Edit .env and add your ANTHROPIC_API_KEY and a strong JWT_SECRET_KEY
```

### 2. Generate JWT Secret

```bash
python -c "import secrets; print(secrets.token_urlsafe(32))"
# Copy output to .env as JWT_SECRET_KEY
```

### 3. Start Services

```bash
docker compose up --build
```

This starts:

- **PostgreSQL** (port 5432) - Database
- **Redis** (port 6379) - Caching & rate limiting
- **FastAPI** (port 8000) - REST API
- **Streamlit** (port 8501) - Web UI

### 4. Initialize Database

```bash
# Create tables and seed initial org + admin user
docker compose exec api python init_db.py --all

# Note the displayed API key and admin credentials
```

### 5. Access Applications

**Web UI:** http://localhost:8501

- Default admin: `admin@example.com` / `admin123`
- ⚠️ **Change the password immediately!**

**API Docs:** http://localhost:8000/api/docs

- Interactive Swagger UI for testing

**API Health:** http://localhost:8000/api/health

---

## 📖 Architecture

```
┌─────────────────┐
│   Streamlit UI  │ ← Web interface (8501)
│   (app.py)      │
└────────┬────────┘
         │
         ├─────────────────┐
         │                 │
┌────────▼────────┐  ┌────▼──────────┐
│   FastAPI API   │  │  PostgreSQL   │
│   (api.py)      │──│   Database    │
└────────┬────────┘  └───────────────┘
         │
    ┌────▼────┐
    │  Redis  │ (optional)
    │ Cache   │
    └─────────┘

Models & Services:
├── models.py          # SQLAlchemy models
├── database.py        # DB session management
├── auth.py            # SSO, JWT, passwords
├── audit.py           # Audit logging
├── admin_dashboard.py # Admin UI
└── api.py             # REST endpoints
```

---

## 🗄️ Database Schema

### Core Tables

- **organizations** - Multi-tenant orgs with SAML config
- **users** - User accounts with roles
- **api_keys** - API authentication with scopes
- **threat_assessments** - Generated threat models
- **audit_logs** - Complete activity tracking
- **usage_stats** - Aggregated analytics
- **api_usage_logs** - Per-request tracking

### Relationships

```
Organization
  ├── Users
  ├── API Keys
  ├── Threat Assessments
  ├── Audit Logs
  └── Usage Stats

User
  ├── API Keys
  ├── Threat Assessments (created)
  └── Audit Logs (actions)
```

---

## 🔧 Configuration

### Environment Variables

**Required:**

```bash
ANTHROPIC_API_KEY=sk-ant-api...
DATABASE_URL=postgresql://user:pass@host:5432/dbname
JWT_SECRET_KEY=your-secure-random-key
```

**Optional:**

```bash
REDIS_URL=redis://localhost:6379/0
FRONTEND_URL=http://localhost:8501
API_RATE_LIMIT_PER_MINUTE=100
LOG_LEVEL=INFO
```

### Organization Settings

Configure per-organization in Admin Dashboard:

- Max users
- Max API calls per month
- Storage limits
- SAML SSO settings (Entity ID, SSO URL, X.509 cert)
- Domain for email-based routing

---

## 🔐 Authentication Flows

### Password Authentication

1. User enters email/password in Streamlit sidebar
2. `PasswordAuth.authenticate()` verifies credentials
3. Session stored in `st.session_state.user`
4. Audit log created

### SSO Authentication (SAML)

1. User enters org slug and clicks "Login with SSO"
2. Redirects to `/saml/login/{org_slug}`
3. API redirects to IdP with SAML request
4. User authenticates with IdP
5. IdP posts SAML response to `/saml/acs/{org_slug}`
6. API validates response, creates/updates user
7. JWT issued in cookie + query param
8. Redirects to Streamlit with token
9. Streamlit reads token, sets session, clears URL

### API Key Authentication

1. Client sends `X-API-Key: tm_xxxxx` header
2. API hashes key and looks up in database
3. Checks if active, not expired
4. Validates required scopes
5. Logs usage to `api_usage_logs`
6. Returns response

---

## 🔌 API Usage Examples

### Create Threat Assessment

```bash
curl -X POST http://localhost:8000/api/v1/threat-modeling \
  -H "Content-Type: application/json" \
  -H "X-API-Key: tm_your_api_key_here" \
  -d '{
    "project_name": "E-Commerce Platform",
    "system_description": "Web application with payment processing, user auth, and admin panel",
    "framework": "STRIDE",
    "risk_type": "Application Security",
    "company_name": "Acme Corp"
  }'
```

### Get Assessment

```bash
curl http://localhost:8000/api/v1/threat-modeling/123 \
  -H "X-API-Key: tm_your_api_key_here"
```

### List Assessments

```bash
curl "http://localhost:8000/api/v1/threat-modeling?limit=10" \
  -H "X-API-Key: tm_your_api_key_here"
```

### View Audit Logs (Admin)

```bash
curl "http://localhost:8000/api/v1/admin/audit-logs?limit=50" \
  -H "X-API-Key: tm_admin_key_here"
```

---

## 🛠️ Development

### Local Setup

1. **Install Python dependencies:**

```bash
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
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

4. **Run API server:**

```bash
uvicorn api:app --reload --port 8000
```

5. **Run Streamlit (separate terminal):**

```bash
streamlit run app.py
```

### Database Migrations

**Create migration:**

```bash
alembic revision --autogenerate -m "Add new feature"
```

**Apply migrations:**

```bash
alembic upgrade head
```

**Rollback:**

```bash
alembic downgrade -1
```

### Adding Sample Data

```bash
python init_db.py --sample-data
```

---

## 🧪 Testing

### Manual Testing

1. Sign in as admin
2. Create a new user
3. Generate an API key
4. Use API to create threat assessment
5. View audit logs
6. Check usage stats

### API Testing

```bash
# Health check
curl http://localhost:8000/api/health

# Test with your API key
export API_KEY="tm_your_key_here"

curl -H "X-API-Key: $API_KEY" \
  http://localhost:8000/api/v1/threat-modeling
```

---

## 📦 Deployment

### Production Checklist

- [ ] Use strong, random `JWT_SECRET_KEY`
- [ ] Set secure PostgreSQL passwords
- [ ] Enable HTTPS (reverse proxy with SSL)
- [ ] Configure proper `FRONTEND_URL`
- [ ] Set `secure=True` for cookies in production
- [ ] Enable database backups
- [ ] Set up monitoring and alerts
- [ ] Configure rate limits
- [ ] Review and adjust resource limits per org
- [ ] Test SAML flow end-to-end
- [ ] Enable audit log retention policy
- [ ] Document disaster recovery procedures

### Docker Production

```bash
# Build optimized image
docker compose -f docker-compose.prod.yml build

# Start with production config
docker compose -f docker-compose.prod.yml up -d

# Check health
curl https://your-domain.com/api/health
```

### Reverse Proxy (nginx example)

```nginx
upstream api {
    server localhost:8000;
}

upstream app {
    server localhost:8501;
}

server {
    listen 443 ssl http2;
    server_name your-domain.com;

    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;

    # API
    location /api/ {
        proxy_pass http://api;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }

    location /saml/ {
        proxy_pass http://api;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }

    # Streamlit
    location / {
        proxy_pass http://app;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
    }
}
```

---

## 📚 Documentation

- **[Enterprise Features Guide](ENTERPRISE_FEATURES.md)** - Detailed feature documentation
- **[API Reference](http://localhost:8000/api/docs)** - Interactive API docs
- **[Installation Guide](INSTALLATION_GUIDE.md)** - Original setup guide

---

## 🔒 Security

### Reporting Security Issues

Please report security vulnerabilities to: security@your-domain.com

### Security Features

- **Encryption:** Passwords hashed with SHA256+salt, JWT tokens signed
- **HTTPS Ready:** Cookie `secure` flag support
- **Rate Limiting:** Per-API-key limits
- **Audit Logging:** Complete activity tracking
- **SAML Security:** Signature validation, certificate checking
- **SQL Injection:** Protected via SQLAlchemy ORM
- **XSS Protection:** Streamlit auto-escaping
- **CSRF:** SAML state validation

---

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

---

## 📄 License

MIT License - See [LICENSE](LICENSE) file for details

---

## 🆘 Support

### Common Issues

**SAML login fails:**

- Check organization SAML settings in Admin Dashboard
- Verify X.509 certificate is valid and in PEM format
- Check IdP configuration matches SP metadata

**API returns 401:**

- Verify API key is correct and active
- Check key hasn't expired
- Ensure key has required scopes

**Database connection error:**

- Ensure PostgreSQL is running
- Check DATABASE_URL format
- Verify network connectivity

**Can't see Admin Dashboard:**

- Sign in with an admin account
- Check user has `is_org_admin=True` or `role='super_admin'`

### Getting Help

1. Check [ENTERPRISE_FEATURES.md](ENTERPRISE_FEATURES.md) for detailed guides
2. Review logs: `docker compose logs api` or `docker compose logs app`
3. Check audit logs in Admin Dashboard
4. File an issue on GitHub

---

## 🎯 Roadmap

- [ ] Advanced rate limiting with burst allowances
- [ ] Webhook notifications for events
- [ ] Custom RBAC roles beyond admin/user
- [ ] SCIM 2.0 for user provisioning
- [ ] Slack/Teams integration
- [ ] Advanced analytics dashboard
- [ ] Export to SARIF, OWASP formats
- [ ] CI/CD integration templates

---

**Built with ❤️ for enterprise security teams**
