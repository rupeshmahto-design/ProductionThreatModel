# Feature Roadmap

## Planned Features

### Critical Risk Dashboard
**Priority:** High  
**Status:** Planned  
**Description:** Executive dashboard providing real-time visibility into critical risks across all assessments and projects.

**Features:**
- Real-time metrics: Total CRITICAL/HIGH/MEDIUM/LOW findings across organization
- Risk trend analysis: Charts showing risk levels over time
- Project risk heatmap: Visual matrix of all projects and their risk scores
- Top 10 critical findings across all assessments
- Overdue remediation tracker (findings past their timeline)
- Risk concentration by category (network, application, data, infrastructure)
- Filtering by project, owner, date range, risk level
- Export dashboard as PDF/Excel for executive reporting
- Customizable widgets and views per user role

**Technical Implementation:**
- Aggregate queries across all ThreatAssessment records
- Time-series data storage for trend analysis
- Chart.js or Plotly for visualizations
- Real-time updates using WebSocket or auto-refresh
- Cached metrics for performance

---

### GRC Platform Integration
**Priority:** High  
**Status:** Planned  
**Description:** Bi-directional integration with Governance, Risk, and Compliance (GRC) platforms to sync findings, risks, and remediation status.

**Supported Platforms:**
- ServiceNow GRC
- RSA Archer
- MetricStream
- LogicGate Risk Cloud
- OneTrust GRC
- Custom GRC via REST API

**Features:**
- Push findings to GRC as risk records automatically
- Sync remediation status both ways
- Map findings to compliance frameworks (NIST, ISO 27001, SOC 2, PCI-DSS)
- Auto-create tickets in GRC for P0/P1 findings
- Pull existing risks from GRC to avoid duplication
- Risk inheritance and aggregation across projects
- Compliance posture reporting

**Technical Requirements:**
- OAuth 2.0 integration with GRC platforms
- REST API clients for each platform
- Webhook listeners for GRC updates
- Field mapping configuration per platform
- Retry logic and error handling

---

### Compliance Framework Mapping
**Priority:** Medium  
**Status:** Planned  
**Description:** Automatically map threat findings to compliance control requirements.

**Supported Frameworks:**
- NIST Cybersecurity Framework (CSF)
- ISO 27001/27002
- SOC 2 Trust Services Criteria
- PCI-DSS
- HIPAA Security Rule
- CIS Controls
- GDPR/Privacy requirements

**Features:**
- Tag findings with applicable compliance controls
- Gap analysis: Show which controls are failing
- Compliance coverage reports per framework
- Multi-framework mapping (one finding → multiple controls)
- Evidence collection for auditors
- Compliance dashboard with coverage percentages

---

### Automated Remediation Tracking
**Priority:** High  
**Status:** Planned  
**Description:** Track remediation progress, send alerts, and manage workflows for fixing findings.

**Features:**
- Assign findings to specific owners/teams
- Set due dates based on priority (P0: 30 days, P1: 90 days)
- Email/Slack notifications for assignments and overdue items
- Status updates: Open → In Progress → Resolved → Verified
- Comments and collaboration on each finding
- Evidence uploads for remediation proof
- Re-assessment triggers after fixes
- SLA tracking and breach alerts
- Bulk status updates

---

### Ticketing System Integration
**Priority:** Medium  
**Status:** Planned  
**Description:** Auto-create tickets for findings in existing ticketing systems.

**Supported Systems:**
- Jira (Software/Service Management)
- ServiceNow (Incident/Change)
- Azure DevOps
- GitHub Issues
- Linear

**Features:**
- Auto-create ticket for each P0/P1 finding
- Configurable ticket templates
- Bi-directional sync: Update finding when ticket closes
- Link findings to existing tickets
- Bulk ticket creation
- Ticket status reflected in assessment view

---

### Vulnerability Scanner Integration
**Priority:** Medium  
**Status:** Planned  
**Description:** Import vulnerability scan results to enrich threat assessments.

**Supported Scanners:**
- Nessus/Tenable.io
- Qualys VMDR
- Rapid7 InsightVM
- OpenVAS
- AWS Inspector
- Azure Defender

**Features:**
- Import CVE findings automatically
- Map vulnerabilities to threat model components
- Prioritize based on CVSS + context
- De-duplicate scan results across time
- Asset correlation with threat model

---

### Risk Trend Analytics
**Priority:** Medium  
**Status:** Planned  
**Description:** Advanced analytics showing risk evolution over time.

**Features:**
- Time-series charts: Risk score trends per project
- Mean-time-to-remediate (MTTR) metrics
- Risk velocity: How fast risks are introduced vs. fixed
- Predictive analytics: Forecast future risk levels
- Comparison views: Current vs. previous assessment
- Version-over-version risk delta
- Export trend reports

---

### API for External Integrations
**Priority:** Medium  
**Status:** Planned  
**Description:** Public REST API for third-party integrations and automation.

**Endpoints:**
- `POST /api/assessments` - Create assessment
- `GET /api/assessments/{id}` - Retrieve assessment
- `GET /api/findings` - List all findings
- `PATCH /api/findings/{id}` - Update finding status
- `GET /api/dashboard/metrics` - Dashboard data
- `POST /api/webhooks` - Register webhooks

**Features:**
- API key authentication
- Rate limiting per client
- Comprehensive API documentation (Swagger/OpenAPI)
- SDKs for Python, JavaScript
- Webhook support for events (new finding, status change)

---

### Scheduled/Recurring Assessments
**Priority:** Low  
**Status:** Planned  
**Description:** Automate periodic threat assessments for ongoing projects.

**Features:**
- Schedule assessments (monthly, quarterly, annually)
- Email reminders to perform assessment
- Auto-generate assessment with updated docs
- Compare against baseline/previous assessment
- Track improvements or degradation over time
- Compliance requirement scheduling (annual reviews)

---

### Custom Risk Scoring Models
**Priority:** Low  
**Status:** Planned  
**Description:** Allow organizations to customize risk calculation formulas.

**Features:**
- Custom likelihood and impact scales (beyond 1-5)
- Weighted risk factors (add business impact multiplier)
- Industry-specific risk models (healthcare, finance, etc.)
- Risk appetite thresholds per organization
- Custom risk level labels (instead of CRITICAL/HIGH/MEDIUM/LOW)

---

### Collaboration & Comments
**Priority:** Medium  
**Status:** Planned  
**Description:** Team collaboration on assessments and findings.

**Features:**
- Comment threads on findings
- @mentions to notify team members
- Assessment review workflow (draft → review → approved)
- Multi-user editing with conflict resolution
- Activity log: Who changed what and when
- Email notifications for comments/mentions

---

### Email & Slack Notifications
**Priority:** Medium  
**Status:** Planned  
**Description:** Proactive alerts for critical events.

**Events:**
- New CRITICAL finding detected
- Remediation deadline approaching
- Assessment completed and ready for review
- Finding status changed
- Overdue remediations

**Channels:**
- Email (configurable per user)
- Slack integration
- Microsoft Teams webhooks
- SMS for P0 findings (optional)

---

### Bulk Import/Export
**Priority:** Low  
**Status:** Planned  
**Description:** Import existing assessments and export data for analysis.

**Features:**
- Import assessments from CSV/Excel
- Import findings from other tools
- Export all data to CSV/Excel/JSON
- Bulk update findings via CSV upload
- Template downloads for imports

---

### Asset Inventory Management
**Priority:** Low  
**Status:** Planned  
**Description:** Maintain inventory of systems/assets being assessed.

**Features:**
- Asset catalog with metadata (owner, criticality, location)
- Link assessments to specific assets
- Asset risk aggregation
- Integration with CMDBs (ServiceNow, Device42)
- Asset lifecycle tracking
- Retired asset handling

---

### Custom Framework Integration (MITRE-Equivalent)
**Priority:** Medium  
**Status:** Planned  
**Description:** Support for client-specific or industry frameworks beyond standard compliance frameworks.

**What We Need from Clients:**

**Option A: Structured Data (Preferred)**
1. **Framework Definition File (JSON/CSV/Excel):**
   - Framework metadata (name, version, owner)
   - Domains/Categories structure
   - Control ID, name, description, severity
   - Risk areas each control covers
   - Testing procedures/evidence requirements
   
2. **Control Mappings (Optional):**
   - Crosswalk to standard frameworks (NIST, ISO, SOC 2)
   - Example: Custom control "INF-01" maps to NIST SC-7, ISO 13.1.3
   
3. **Risk Scoring Model:**
   - Custom likelihood/impact scales (if different from 1-5)
   - Risk calculation formulas
   - Risk level thresholds (what score = CRITICAL vs HIGH)
   
4. **Compliance Requirements:**
   - Mandatory vs. optional controls
   - Evidence types required
   - Testing frequency per control
   - Ownership assignment rules

**Option B: Framework Document (Common Reality)**
Many clients have their framework in PDF/Word/PowerPoint documents. We can handle this:

1. **Client provides framework document:**
   - PDF: "Acme Security Assessment Framework v3.pdf"
   - Word: "Company Risk Control Framework.docx"
   - PowerPoint: "Security Control Library.pptx"
   
2. **We use AI to extract structured data:**
   - Upload document to platform
   - Claude AI parses document to extract:
     - Framework name and version
     - Domain/category structure
     - Control IDs, names, descriptions
     - Risk levels and scoring methodology
     - Testing/evidence requirements
   - Generate structured JSON automatically
   - Show preview for client review/editing
   
3. **Human-in-the-loop validation:**
   - Display extracted framework in editable UI
   - Client reviews and corrects any AI extraction errors
   - Client fills in missing fields (severity, mappings)
   - Save as structured framework in database

**Hybrid Approach:**
- First import: AI extracts from document
- Client reviews/refines via UI form
- Export as JSON for future use
- Support versioning when framework document updates

**Implementation:**
- Framework upload interface supporting:
  - Structured: JSON/CSV/Excel import
  - Documents: PDF/Word/PowerPoint upload
- **AI-Powered Document Parser:**
  - Use Claude API (same as threat assessments)
  - Extract framework structure from narrative documents
  - Prompt: "Extract all security controls, domains, IDs, descriptions, and risk levels from this framework document"
  - Parse tables, numbered lists, hierarchies
  - Handle common formats (NIST-style, ISO-style, custom)
- Schema validation for framework structure
- **Interactive Review UI:**
  - Show extracted framework in editable table
  - Highlight low-confidence extractions for review
  - Allow adding missing fields (severity, mappings)
  - Bulk edit capabilities
- Store in database: frameworks, domains, controls tables
- Framework selection dropdown in assessment form
- Map threat findings to framework controls automatically
- Generate compliance gap reports
- Support multiple active frameworks per organization
- Version control for framework changes

**User Workflow (Document Upload):**
1. Admin uploads "Company_Framework_2026.pdf"
2. AI extracts: 5 domains, 47 controls detected
3. Preview table shows: Control IDs, names, descriptions
4. Admin reviews, fixes "Data Encryption" severity (AI guessed Medium, should be High)
5. Admin adds NIST mappings for key controls
6. Save as "Company Framework v2.0"
7. Now available in assessment form dropdown

**Example Client Frameworks:**
- Banking: Custom PCI-DSS extension
- Healthcare: Enhanced HIPAA + state regulations
- Manufacturing: OT/ICS security framework
- Government: Agency-specific NIST variant
- Aerospace: CMMC with custom controls

**API Example:**
```json
POST /api/frameworks/import
{
  "framework": {
    "name": "Acme Corp Security Framework 2026",
    "version": "3.0",
    "domains": [...],
    "controls": [...]
  }
}
```

---

### Owner Assignment Strategy
**Priority:** High  
**Status:** Planned  
**Description:** Clarify owner assignment workflow - in-platform vs. GRC system.

**Vanta's Approach (Research Findings):**
- Assigns owners WITHIN Vanta platform
- Integrates with Jira/Asana/GitHub to push action items
- Maintains single source of truth in Vanta
- Bi-directional sync: status updates flow back from ticketing systems

**Our Recommended Approach:**
1. **Primary assignment in OUR platform:**
   - Assign owner/team to each finding
   - Track status internally (Open → In Progress → Resolved)
   - Due dates and SLA tracking
   
2. **Optional GRC/Ticketing push:**
   - Button: "Create Jira Ticket" or "Push to ServiceNow"
   - Auto-create ticket with finding details
   - Link ticket ID back to finding
   - Webhook/API to sync status changes
   
3. **Flexibility for clients:**
   - Small orgs: Manage everything in our platform
   - Enterprise: Assign in our platform, work in existing tools
   - Pure GRC mode: Push all findings to GRC immediately

**Benefits:**
- Teams work where they're comfortable
- Audit trail maintained in both systems
- No forced adoption of new tools
- Supports diverse client workflows

---

### Jira Integration
**Priority:** Medium  
**Status:** Planned  
**Description:** Integrate with Atlassian Jira to automatically load project documents and context for threat assessments.

**Features:**
- Connect to Jira Cloud or Self-Hosted instances
- Authenticate using API tokens or OAuth 2.0
- Fetch attachments from specific Jira issues (by issue key)
- Extract issue descriptions, comments, and custom fields as context
- Optional: Fetch all documentation from entire Jira project
- Add UI option: "Upload Files" or "Load from Jira"

**Technical Requirements:**
- Add `jira==3.5.1` library dependency
- Store Jira credentials securely (encrypted in database or env vars)
- Add Jira configuration settings page
- Create document fetching service
- Handle various attachment types (PDF, Word, Excel, images)

**User Workflow:**
1. Configure Jira connection (URL, email, API token)
2. In threat assessment form, select "Load from Jira"
3. Enter Jira issue key (e.g., "PROJ-123")
4. System fetches and displays available attachments
5. User selects documents to include in assessment
6. Proceed with threat assessment as normal

---

## Completed Features
- ✅ Project number field for grouping assessments
- ✅ Version history view grouped by project
- ✅ PDF export with colored risk levels
- ✅ Security enhancements (bcrypt, rate limiting, input validation)
- ✅ Multi-tenancy support
- ✅ RBAC with admin/analyst roles
- ✅ AI-powered threat assessment with Claude
