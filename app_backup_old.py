"""
AI-Powered Threat Modeling Tool
Complete user management and assessment history system
"""

import streamlit as st
import os
import io
import sys
from datetime import datetime
from pathlib import Path
import json
import base64
import anthropic
import simple_storage as storage

# Page configuration
st.set_page_config(
    page_title="AI Threat Modeling Tool",
    page_icon="🔒",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for beautiful, client-facing UI
st.markdown("""
    <style>
    * {
        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Roboto', sans-serif;
    }
    
    .main {
        background: #f8fafc;
        min-height: 100vh;
    }
    
    h1 {
        color: #0f172a !important;
        font-weight: 700 !important;
        font-size: 2.2rem !important;
        margin-bottom: 0.2rem !important;
    }
    
    h2 {
        color: #1e293b !important;
        font-weight: 700 !important;
        font-size: 1.5rem !important;
        margin-top: 1.5rem !important;
        margin-bottom: 1rem !important;
        border-bottom: 3px solid #3b82f6 !important;
        padding-bottom: 0.5rem !important;
    }
    
    h3 {
        color: #334155 !important;
        font-weight: 600 !important;
        font-size: 1.1rem !important;
    }
    
    /* Button styling */
    .stButton>button {
        background: linear-gradient(135deg, #3b82f6 0%, #2563eb 100%) !important;
        color: white !important;
        border-radius: 8px !important;
        padding: 0.75rem 2rem !important;
        font-weight: 600 !important;
        font-size: 0.95rem !important;
        border: none !important;
        transition: all 0.3s ease !important;
        box-shadow: 0 2px 8px rgba(59, 130, 246, 0.3) !important;
    }
    
    .stButton>button:hover {
        background: linear-gradient(135deg, #2563eb 0%, #1d4ed8 100%) !important;
        transform: translateY(-2px) !important;
        box-shadow: 0 4px 12px rgba(59, 130, 246, 0.4) !important;
    }
    
    /* Input fields - EXCELLENT CONTRAST */
    .stTextInput > div > div > input,
    .stSelectbox > div > div > select,
    .stNumberInput > div > div > input {
        background: white !important;
        border: 2px solid #cbd5e1 !important;
        color: #0f172a !important;
        border-radius: 8px !important;
        padding: 0.7rem 1rem !important;
        font-size: 1rem !important;
    }
    
    .stTextInput > div > div > input::placeholder {
        color: #94a3b8 !important;
    }
    
    .stTextInput > div > div > input:focus,
    .stSelectbox > div > div > select:focus,
    .stNumberInput > div > div > input:focus {
        border-color: #3b82f6 !important;
        box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.1) !important;
    }
    
    /* Labels - High Contrast */
    .stTextInput > label,
    .stSelectbox > label,
    .stNumberInput > label,
    .stMultiSelect > label {
        color: #1e293b !important;
        font-weight: 600 !important;
        font-size: 0.95rem !important;
        margin-bottom: 0.4rem !important;
    }
    
    /* Checkbox */
    .stCheckbox > label {
        color: #1e293b !important;
        font-weight: 500 !important;
    }
    
    .stCheckbox > label > span {
        color: #475569 !important;
    }
    
    /* Multiselect */
    .stMultiSelect > div > div > div {
        background: white !important;
        border: 2px solid #cbd5e1 !important;
    }
    
    /* Expanders */
    .streamlit-expanderHeader {
        background: #f1f5f9 !important;
        border: 1px solid #e2e8f0 !important;
        border-radius: 8px !important;
        padding: 1rem !important;
    }
    
    .streamlit-expanderHeader:hover {
        background: #e8eef7 !important;
    }
    
    /* Alert messages - Better contrast */
    .stSuccess {
        background: #f0fdf4 !important;
        border: 2px solid #86efac !important;
        border-radius: 8px !important;
        padding: 1rem !important;
        color: #166534 !important;
    }
    
    .stWarning {
        background: #fffbeb !important;
        border: 2px solid #fde047 !important;
        border-radius: 8px !important;
        padding: 1rem !important;
        color: #92400e !important;
    }
    
    .stError {
        background: #fef2f2 !important;
        border: 2px solid #fca5a5 !important;
        border-radius: 8px !important;
        padding: 1rem !important;
        color: #7f1d1d !important;
    }
    
    .stInfo {
        background: #eff6ff !important;
        border: 2px solid #bfdbfe !important;
        border-radius: 8px !important;
        padding: 1rem !important;
        color: #1e40af !important;
    }
    
    /* Framework cards */
    .framework-card {
        background: white !important;
        border: 2px solid #e2e8f0 !important;
        padding: 1.5rem !important;
        border-radius: 12px !important;
        margin: 1rem 0 !important;
        transition: all 0.3s !important;
    }
    
    .framework-card:hover {
        border-color: #3b82f6 !important;
        box-shadow: 0 4px 12px rgba(59, 130, 246, 0.15) !important;
    }
    
    .framework-card.selected {
        background: #eff6ff !important;
        border-color: #3b82f6 !important;
        box-shadow: 0 4px 16px rgba(59, 130, 246, 0.2) !important;
    }
    
    .framework-card h4 {
        margin-top: 0 !important;
        margin-bottom: 0.6rem !important;
        color: #1e293b !important;
        font-size: 1.1rem !important;
    }
    
    .framework-card p {
        margin: 0.3rem 0 !important;
        color: #475569 !important;
        font-size: 0.95rem !important;
    }
    
    /* Upload box */
    .upload-box {
        border: 3px dashed #3b82f6 !important;
        border-radius: 12px !important;
        padding: 2.5rem 2rem !important;
        text-align: center !important;
        background: linear-gradient(135deg, #eff6ff 0%, #f0f9ff 100%) !important;
        margin: 1rem 0 !important;
    }
    
    .upload-box h3 {
        color: #1e293b !important;
        margin: 0.5rem 0 !important;
    }
    
    .upload-box p {
        color: #475569 !important;
        margin: 0.3rem 0 !important;
    }
    
    /* Sidebar */
    [data-testid="stSidebar"] {
        background: #1e293b;
    }
    
    [data-testid="stSidebar"] h2,
    [data-testid="stSidebar"] h3,
    [data-testid="stSidebar"] label {
        color: #e2e8f0 !important;
    }
    
    [data-testid="stSidebar"] p {
        color: #cbd5e1 !important;
    }
    
    .header-subtitle {
        color: #64748b !important;
        font-size: 1rem !important;
        margin-bottom: 1.5rem !important;
    }
    
    hr {
        border: none !important;
        height: 1px !important;
        background: #e2e8f0 !important;
        margin: 1.5rem 0 !important;
    }
    
    </style>
""", unsafe_allow_html=True)

# Initialize session state
if 'assessment_complete' not in st.session_state:
    st.session_state.assessment_complete = False
if 'threat_report' not in st.session_state:
    st.session_state.threat_report = None
if 'uploaded_files' not in st.session_state:
    st.session_state.uploaded_files = []
if 'processing' not in st.session_state:
    st.session_state.processing = False
if 'logo_image' not in st.session_state:
    st.session_state.logo_image = None
if 'company_name' not in st.session_state:
    st.session_state.company_name = ""
if 'report_footer' not in st.session_state:
    st.session_state.report_footer = ""
if 'project_name_input' not in st.session_state:
    st.session_state.project_name_input = ""
if 'show_reset_confirm' not in st.session_state:
    st.session_state.show_reset_confirm = False
if 'user' not in st.session_state:
    st.session_state.user = None

# Initialize JWT secret for verifying SSO token
if ENTERPRISE_ENABLED:
    try:
        secret = os.getenv("JWT_SECRET_KEY") or "dev-secret-change-me"
        SessionManager.init_secret_key(secret)
    except Exception:
        pass

# Capture JWT from query params to auto-login after SSO
if ENTERPRISE_ENABLED:
    try:
        params = st.query_params
        if 'token' in params and not st.session_state.user:
            token = params['token']
            db: Session = SessionLocal()
            try:
                user = SessionManager.get_user_from_token(token, db)
                if user and user.is_active:
                    st.session_state.user = user
                    # Clear token from URL
                    st.query_params.clear()
                    st.toast("Signed in via SSO", icon="✅")
            finally:
                db.close()
    except Exception:
        pass


def _render_login_sidebar():
    if not ENTERPRISE_ENABLED:
        return
    
    st.sidebar.markdown("## Account")
    db: Session = SessionLocal()
    try:
        if st.session_state.user:
            u = st.session_state.user
            st.sidebar.success(f"✅ **{u.full_name or u.username}**")
            st.sidebar.caption(f"{u.email}")
            if u.is_org_admin or u.role == 'super_admin':
                st.sidebar.info("👑 Admin")
            if st.sidebar.button("🚪 Sign out"):
                st.session_state.user = None
                st.rerun()
        else:
            with st.sidebar.expander("🔐 Sign in", expanded=True):
                email = st.text_input("Email", key="login_email")
                password = st.text_input("Password", type="password", key="login_pwd")
                if st.button("Sign in"):
                    user = PasswordAuth.authenticate(email=email, password=password, db=db)
                    if user:
                        st.session_state.user = user
                        st.success("Signed in")
                        st.rerun()
                    else:
                        st.error("Invalid credentials")
            with st.sidebar.expander("🏢 Enterprise SSO", expanded=False):
                org_slug = st.text_input("Organization Slug", key="sso_org_slug", placeholder="e.g., default")
                if st.button("Login with SSO"):
                    if org_slug:
                        sso_url = f"http://localhost:8000/saml/login/{org_slug}"
                        st.sidebar.markdown(f"[Continue to SSO →]({sso_url})")
                    else:
                        st.warning("Enter organization slug")
    finally:
        db.close()


def _maybe_render_admin():
    if not ENTERPRISE_ENABLED or not st.session_state.user:
        return
    if st.session_state.user.is_org_admin or st.session_state.user.role == 'super_admin':
        import admin_dashboard
        admin_dashboard.render_admin_dashboard()
        st.stop()

_render_login_sidebar()

# Show signed-in status in main area
if ENTERPRISE_ENABLED and st.session_state.user:
    user = st.session_state.user
    col1, col2 = st.columns([4, 1])
    with col1:
        st.markdown(f"<p style='color: #64748b; font-size: 0.9rem;'>Signed in as <strong>{user.email}</strong></p>", unsafe_allow_html=True)
    with col2:
        if user.is_org_admin or user.role == 'super_admin':
            st.markdown("<p style='text-align: right; color: #3b82f6; font-size: 0.9rem;'>👑 Admin Access</p>", unsafe_allow_html=True)

# Top-level tabs: Threat Modeling and Admin (if admin)
if ENTERPRISE_ENABLED and st.session_state.user and (st.session_state.user.is_org_admin or st.session_state.user.role == 'super_admin'):
    tab_main, tab_admin = st.tabs(["🛡️ Threat Modeling", "⚙️ Admin Dashboard"])
    with tab_admin:
        import admin_dashboard
        admin_dashboard.render_admin_dashboard()
    with tab_main:
        pass  # Main content below
else:
    st.markdown("---")

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

# Model families that should always use the Messages API (case-insensitive substring match)
PREFERRED_MESSAGES_API_FAMILIES = [
    "claude",
]

def extract_text_from_file(uploaded_file):
    """Extract text content from uploaded files"""
    try:
        file_extension = Path(uploaded_file.name).suffix.lower()
        
        if file_extension in ['.txt', '.md']:
            return uploaded_file.getvalue().decode('utf-8')
        elif file_extension == '.pdf':
            # For PDF, we'll just note the filename and ask Claude to understand it's a PDF
            return f"[PDF Document: {uploaded_file.name}]"
        else:
            return f"[{file_extension.upper()} Document: {uploaded_file.name}]"
    except Exception as e:
        return f"[Error reading {uploaded_file.name}: {str(e)}]"

def _suggest_references_from_text(text):
    """Return a set of suggested short citations (text, url) based on keywords in the report."""
    suggestions = set()

    # Small keyword -> citation mapping (can be extended)
    MAPPING = {
        'prompt injection': ("OWASP Prompt Injection Guidance", "https://owasp.org/"),
        'prompt-injection': ("OWASP Prompt Injection Guidance", "https://owasp.org/"),
        'injection': ("OWASP Top 10", "https://owasp.org/www-project-top-ten/"),
        'mitre': ("MITRE ATT&CK", "https://attack.mitre.org/"),
        'privilege escalation': ("CWE-269 Privilege Not Checked", "https://cwe.mitre.org/") ,
        'data exfiltration': ("NIST SP 800-53", "https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final"),
        'compliance': ("ISO 27001", "https://www.iso.org/isoiec-27001-information-security.html"),
        'agent': ("AI Safety Papers", "https://arxiv.org/"),
    }

    lower = text.lower()
    for k, v in MAPPING.items():
        if k in lower:
            suggestions.add(v)
    return suggestions


def _merge_references_section(report_md, suggestions):
    """Ensure suggestions (set of (text,url)) appear in the REFERENCES section of report_md.
    Returns the updated markdown.
    """
    if not suggestions:
        return report_md

    # Find if a REFERENCES section exists
    lines = report_md.splitlines()
    ref_idx = None
    for i, line in enumerate(lines):
        if line.strip().upper().startswith('## REFERENCES') or line.strip().upper().startswith('# REFERENCES'):
            ref_idx = i
            break

    # Build suggestion lines
    suggestion_lines = [f"- [{text}] {url}" for (text, url) in sorted(suggestions)]

    if ref_idx is None:
        # Append a References section
        if not report_md.endswith('\n'):
            report_md += '\n'
        report_md += '\n## REFERENCES\n' + '\n'.join(suggestion_lines) + '\n'
        return report_md

    # If references section exists, find its end (next top-level heading or EOF)
    end_idx = len(lines)
    for j in range(ref_idx + 1, len(lines)):
        if lines[j].startswith('#'):
            end_idx = j
            break

    # Collect existing refs
    existing = set(l.strip() for l in lines[ref_idx+1:end_idx] if l.strip())
    for s in suggestion_lines:
        if s not in existing:
            existing.add(s)

    new_refs = ['## REFERENCES'] + sorted(existing)
    new_lines = lines[:ref_idx] + new_refs + lines[end_idx:]
    return '\n'.join(new_lines)


def reset_assessment_form():
    """Reset all form fields and clear previous assessment"""
    st.session_state.assessment_complete = False
    st.session_state.threat_report = None
    st.session_state.uploaded_files = []
    st.session_state.processing = False
    st.session_state.project_name_input = ""
    st.session_state.show_reset_confirm = False


def generate_threat_assessment(project_info, documents_content, framework, risk_areas, api_key):
    """Generate comprehensive threat assessment using SecureAI"""
    
    client = anthropic.Anthropic(api_key=api_key)
    
    # Build comprehensive prompt
    prompt = f"""You are an expert cybersecurity consultant specializing in threat modeling and risk assessment. 
Perform a comprehensive threat assessment for the following project using the {framework} framework.

**PROJECT INFORMATION:**
- Project Name: {project_info['name']}
- Application Type: {project_info['app_type']}
- Deployment Model: {project_info['deployment']}
- Business Criticality: {project_info['criticality']}
- Compliance Requirements: {', '.join(project_info['compliance'])}

**UPLOADED DOCUMENTATION:**
{documents_content}

**THREAT MODELING FRAMEWORK:** {framework}
{FRAMEWORKS[framework]['description']}

**SPECIFIC RISK FOCUS AREAS TO ASSESS:**
{chr(10).join([f"- {area}: {RISK_AREAS[area]['description']}" for area in risk_areas])}

**ASSESSMENT REQUIREMENTS - EVIDENCE-BASED ANALYSIS:**

Generate a professional threat assessment report with complete structure, extensive tables, and and color-coded risk levels suitable for executive review.

**CRITICAL REQUIREMENT: Every finding, recommendation, and observation MUST include:**
1. **Document Reference:** Which uploaded document this observation is from
2. **Evidence Citation:** Specific quote or observation from the document
3. **Line Context:** Approximate location/section in the document  
4. **Analysis:** How this evidence leads to the threat assessment finding
5. **Concrete Examples:** Specific examples from the documentation demonstrating the issue/risk

**Document Analysis Instructions:**
- Review ALL uploaded documentation thoroughly
- For each finding, identify the specific document evidence that supports it
- Include document names/identifiers in citations
- Quote or paraphrase key observations that led to the finding
- If a finding is based on multiple documents, reference all relevant sources
- For architecture diagrams, reference specific components mentioned
- For code samples, reference specific issues or patterns observed

**CONCRETE EXAMPLES REQUIREMENT:**
For every major finding, include at least ONE concrete example directly from the uploaded documents:
- If documentation mentions specific features/configurations → cite them by name and location
- If code samples are provided → reference specific lines or code patterns
- If architecture diagrams are shown → reference specific components and their interactions
- If configuration files are included → cite specific parameters and values
- Use formatting like: **EXAMPLE from [Document Name]:** [specific example with exact details from doc]

**Example Evidence Format to Follow:**
"[Based on uploaded document: Architecture_Design_v2.pdf] The system architecture mentions that 150+ autonomous AI agents have elevated privileges (page 3, 'Agent Permissions' section: 'All agents deployed with admin-level access to financial systems'). 

**EXAMPLE from Architecture_Design_v2.pdf:** The document states on page 4: 'Agents can access: database admin credentials, API keys, payment processing tokens, customer data repositories' without role-based restrictions.

This creates risk finding F001 because unrestricted privilege elevation enables unauthorized actions including data theft and financial fraud [see also: Configuration_Guide.md, section 'Agent Capability Levels']."

# EXECUTIVE SUMMARY

**Overall Risk Rating:** [CRITICAL/HIGH/MEDIUM/LOW]

[One paragraph describing assessment scope, methodology, and documents reviewed]

## Top 5 Critical Findings (with Document Evidence & Examples)

| Finding | Evidence Source (Doc) | Example from Docs | Risk Level | Business Impact | Timeline |
|---------|-----------------------|-------------------|-----------|-----------------|-----------|
| [Finding 1 with doc ref] | [Document: Name/Section] | [Specific example from doc] | CRITICAL | [Impact description] | Immediate (0-30 days) |
| [Finding 2 with doc ref] | [Document: Name/Section] | [Specific example from doc] | HIGH | [Impact description] | Short-term (30-90 days) |
| [Finding 3 with doc ref] | [Document: Name/Section] | [Specific example from doc] | HIGH | [Impact description] | Short-term (30-90 days) |
| [Finding 4 with doc ref] | [Document: Name/Section] | [Specific example from doc] | MEDIUM | [Impact description] | Medium-term (90-180 days) |
| [Finding 5 with doc ref] | [Document: Name/Section] | [Specific example from doc] | MEDIUM | [Impact description] | Medium-term (90-180 days) |

## Key Recommendations Summary

| Priority | Count | Sample Actions |
|----------|-------|-----------------|
| P0 - CRITICAL | [count] | Immediate mitigations for critical risks |
| P1 - HIGH | [count] | High-priority security improvements |
| P2 - MEDIUM | [count] | Medium-term strengthening measures |
| P3 - LOW | [count] | Long-term defense-in-depth initiatives |

---

# THREAT MODELING ANALYSIS - {framework}

Comprehensive threat analysis organized by {framework} categories with risk scoring and mitigation paths, **with evidence citations and concrete examples from uploaded documentation**.

For each relevant category in {framework}, provide detailed analysis:

## [Category Name]

[Introduction paragraph with document evidence references]

| Threat ID | Threat Description | Document Evidence | Example from Documentation | Likelihood | Impact | Risk Score | Recommended Mitigation |
|-----------|-------------------|-------------------|---------------------------|-----------|--------|-----------|----------------------|
| T001 | [threat description] | [Doc: Name, Section/Quote] | [Specific example from doc] | [1-5] | [1-5] | [score] | [mitigation] |

---

# SPECIALIZED RISK ASSESSMENTS

Detailed analysis of specific risk areas with threat matrices and mitigation strategies, **each with specific document references, evidence citations, and concrete examples from documentation**.

{chr(10).join([f'''## {area}

[Introduction paragraph about {area}]

| Threat ID | Evidence Source (Doc) | Example from Docs | Threat | Likelihood | Impact | Risk Priority | Mitigation Strategy |
|-----------|-----------------------|-------------------|--------|-----------|--------|---------------|---------------------|
| T-{area[:3].upper()}-001 | [Doc: Section] | [Specific example] | [specific threat] | [1-5] | [1-5] | P0/P1/P2 | [specific action] |
''' for area in risk_areas])}

---

# COMPONENT-SPECIFIC THREAT ANALYSIS

Threats organized by system architecture components with detection and response strategies, **including concrete examples from uploaded documentation**.

| Component | Document Evidence | Example from Docs | Critical Threats | Risk Level | Mitigation Approach |
|-----------|-------------------|-------------------|-----------------|-----------|---------------------|
| Frontend/UI | [Doc: Section] | [example from doc] | [threats] | CRITICAL/HIGH | [approach] |
| Backend/App | [Doc: Section] | [example from doc] | [threats] | CRITICAL/HIGH | [approach] |
| Database/Data | [Doc: Section] | [example from doc] | [threats] | CRITICAL/HIGH | [approach] |
| API/Integration | [Doc: Section] | [example from doc] | [threats] | CRITICAL/HIGH | [approach] |
| Infrastructure | [Doc: Section] | [example from doc] | [threats] | CRITICAL/HIGH | [approach] |
| Cloud Services | [Doc: Section] | [example from doc] | [threats] | CRITICAL/HIGH | [approach] |

---

# ATTACK SCENARIOS & KILL CHAINS

Realistic attack progression models showing attacker techniques and defense opportunities, **with evidence from uploaded documentation showing how system features enable each phase**.

## Scenario 1: [Attack Title - Highest Risk Scenario from Document Evidence]

[Context paragraph with reference to specific system features mentioned in uploaded docs]

| Kill Chain Phase | Document Evidence | Example from Docs | Description | Detection Window | Mitigation Strategy |
|-----------------|-------------------|-------------------|-------------|------------------|---------------------|
| Reconnaissance | [Doc: Section] | [example from doc] | [phase details] | [detection opportunity] | [mitigation] |
| Weaponization | [Doc: Section] | [example from doc] | [phase details] | [detection opportunity] | [mitigation] |
| Delivery | [Doc: Section] | [example from doc] | [phase details] | [detection opportunity] | [mitigation] |
| Exploitation | [Doc: Section] | [example from doc] | [phase details] | [detection opportunity] | [mitigation] |
| Installation | [Doc: Section] | [example from doc] | [phase details] | [detection opportunity] | [mitigation] |
| C2 & Control | [Doc: Section] | [example from doc] | [phase details] | [detection opportunity] | [mitigation] |
| Exfiltration | [Doc: Section] | [example from doc] | [phase details] | [detection opportunity] | [mitigation] |

**Evidence from Documentation:** [Cite specific doc sections that enable this attack scenario]  
**Impact:** [Business impact of successful attack]  
**Detection Probability:** [likelihood of catching attack]  
**Response Strategy:** [recommended defense approach]

---

# COMPREHENSIVE RISK MATRIX

All findings mapped to risk levels with prioritization.

## Risk Score Calculation

| Likelihood (L) | 1 - Rare | 2 - Unlikely | 3 - Possible | 4 - Likely | 5 - Very Likely |
|---|---|---|---|---|---|
| **5 - Catastrophic** | 5 | 10 | 15 | 20 | **25-CRITICAL** |
| **4 - Major** | 4 | 8 | 12 | **16-HIGH** | **20-CRITICAL** |
| **3 - Moderate** | 3 | 6 | **9-MEDIUM** | **12-HIGH** | **15-HIGH** |
| **2 - Minor** | 2 | **4-LOW** | **6-MEDIUM** | **8-MEDIUM** | **10-HIGH** |
| **1 - Minimal** | **1-LOW** | **2-LOW** | **3-LOW** | **4-LOW** | **5-LOW** |

## All Findings Risk Matrix

| Finding ID | Description | Likelihood | Impact | Risk Score | Risk Level | Priority | Owner | Remediation Timeline |
|----------|-------------|-----------|--------|-----------|-----------|----------|-------|----------------------|
| F001 | [critical finding] | [1-5] | [1-5] | [score] | **CRITICAL** | P0 | [owner] | 0-30 days |
| F002 | [high finding] | [1-5] | [1-5] | [score] | **HIGH** | P1 | [owner] | 30-90 days |
| F003 | [medium finding] | [1-5] | [1-5] | [score] | **MEDIUM** | P2 | [owner] | 90-180 days |

---

# PRIORITIZED RECOMMENDATIONS

All recommendations organized by priority tier with implementation details and risk reduction impact.

## P0 - CRITICAL (Remediate in 0-30 days)

**These findings represent immediate threats requiring urgent action.**

| Rec ID | Recommendation | Current Risk | Risk Reduction | Implementation Steps | Required Effort | Owner | Target Completion | Dependencies |
|--------|---------------|--------------|----------------|---------------------|-----------------|-------|------------------|-----------------|
| R001 | [action] | Critical | [% reduction] | [step 1, 2, 3...] | [effort estimate] | [owner] | [date] | [dependencies] |
| R002 | [action] | Critical | [% reduction] | [step 1, 2, 3...] | [effort estimate] | [owner] | [date] | [dependencies] |

## P1 - HIGH (Remediate in 30-90 days)

**High-priority improvements that significantly reduce risk exposure.**

| Rec ID | Recommendation | Current Risk | Risk Reduction | Implementation Steps | Required Effort | Owner | Target Completion | Dependencies |
|--------|---------------|--------------|----------------|---------------------|-----------------|-------|------------------|-----------------|
| R010 | [action] | High | [% reduction] | [step 1, 2, 3...] | [effort estimate] | [owner] | [date] | [dependencies] |
| R011 | [action] | High | [% reduction] | [step 1, 2, 3...] | [effort estimate] | [owner] | [date] | [dependencies] |

## P2 - MEDIUM (Remediate in 90-180 days)

**Medium-term security improvements for sustained risk reduction.**

| Rec ID | Recommendation | Current Risk | Risk Reduction | Implementation Steps | Required Effort | Owner | Target Completion | Dependencies |
|--------|---------------|--------------|----------------|---------------------|-----------------|-------|------------------|-----------------|
| R020 | [action] | Medium | [% reduction] | [step 1, 2, 3...] | [effort estimate] | [owner] | [date] | [dependencies] |

## P3 - LOW (Remediate in 180+ days)

**Long-term enhancements and defense-in-depth measures.**

| Rec ID | Recommendation | Current Risk | Risk Reduction | Implementation Steps | Required Effort | Owner | Target Completion | Dependencies |
|--------|---------------|--------------|----------------|---------------------|-----------------|-------|------------------|-----------------|
| R030 | [action] | Low | [% reduction] | [step 1, 2, 3...] | [effort estimate] | [owner] | [date] | [dependencies] |

---

# SECURITY CONTROLS MAPPING

Recommendations mapped to control categories and compliance frameworks.

| Control Category | Control Name | Implementation Status | Addresses Finding | Compliance Requirement | Timeline |
|-----------------|--------------|----------------------|-------------------|----------------------|----------|
| Preventive | [control] | [Not Started/In Progress/Implemented] | [F-ID] | [framework] | [timeline] |
| Detective | [control] | [Not Started/In Progress/Implemented] | [F-ID] | [framework] | [timeline] |
| Corrective | [control] | [Not Started/In Progress/Implemented] | [F-ID] | [framework] | [timeline] |
| Compensating | [control] | [Not Started/In Progress/Implemented] | [F-ID] | [framework] | [timeline] |

---

# COMPLIANCE CONSIDERATIONS

Map all findings to required compliance frameworks:

| Finding ID | Finding | Compliance Requirement | Compliance Gap | Required Evidence | Remediation Timeline |
|----------|---------|----------------------|----------------|------------------|---------------------|
{chr(10).join([f"| [F-ID] | [finding] | {req} | [gap description] | [evidence needed] | [timeline] |" for req in project_info['compliance']])}

---

# SECURITY METRICS & KPIs

Establish tracking metrics for continuous security improvement:

| Metric | Current State | Target State | Measurement Method | Reporting Frequency | Owner |
|--------|--------------|--------------|-------------------|--------------------|------------|
| MTTD (Mean Time to Detect) | [current] | [target] | [method] | Weekly | [owner] |
| MTTR (Mean Time to Respond) | [current] | [target] | [method] | Weekly | [owner] |
| Active Critical Vulnerabilities | [current] | 0 | [method] | Weekly | [owner] |
| Patch Compliance % | [current] | 98% | [method] | Bi-weekly | [owner] |
| Security Training Completion % | [current] | 100% | [method] | Quarterly | [owner] |
| Incident Response Drills | [current] | [target] | [method] | Quarterly | [owner] |

---

# APPENDICES

## A. THREAT TAXONOMY & REFERENCE FRAMEWORKS

**Security Frameworks Referenced:**
- NIST SP 800-53 Rev 5 (Security and Privacy Controls)
- OWASP Top 10 2021 (Application Security Risks)
- MITRE ATT&CK Framework (Adversary Tactics & Techniques)
- ISO/IEC 27001:2013 (Information Security Management)
- CIS Controls v8 (Critical Security Controls)

## B. RISK RATING METHODOLOGY

**Risk Score Calculation:** Likelihood (1-5) × Impact (1-5) = Risk Score (1-25)

**Risk Level Classification:**

| Score Range | Risk Level | Response Time | Typical Examples |
|-------------|-----------|---------------|------------------|
| 20-25 | **CRITICAL** | 0-30 days | Active exploitation, data breach, RCE vulnerabilities |
| 12-19 | **HIGH** | 30-90 days | Privilege escalation, authentication bypass, significant exposure |
| 6-11 | **MEDIUM** | 90-180 days | Information disclosure, weak configurations, missing controls |
| 1-5 | **LOW** | 180+ days | Low-impact findings, defense-in-depth improvements |

## C. TOOLS & TECHNOLOGY RECOMMENDATIONS

Recommended security tooling by category:

| Category | Recommended Tools | Purpose | Implementation Priority |
|----------|------------------|---------|------------------------|
| Vulnerability Scanning | [tools] | Automated vulnerability detection | P0 |
| SIEM/Monitoring | [tools] | Security event monitoring & correlation | P0 |
| Incident Response | [tools] | Threat detection & response automation | P1 |
| Compliance | [tools] | Compliance tracking & reporting | P1 |
| Penetration Testing | [tools] | Offensive security testing | P1 |
| Code Analysis | [tools] | SAST/DAST security testing | P2 |

---

**CRITICAL FORMATTING REQUIREMENTS FOR EXECUTIVE-READY OUTPUT:**

1. **Table Usage:** All findings, recommendations, risk matrices, and comparisons MUST use markdown tables
2. **Color-Coded Risk Levels:** Always use **CRITICAL** (red), **HIGH** (orange), **MEDIUM** (yellow), **LOW** (green)
3. **Unique Identifiers:** Use F### for findings, R### for recommendations, T### for threats for cross-referencing
4. **Proper Spacing:** Add blank lines between sections and use --- for major section breaks
5. **Page Break Hints:** Major sections (Executive Summary, Risk Matrix, Recommendations) naturally break
6. **Headers:** Consistent H1 (#) for major sections, H2 (##) for subsections, H3 (###) for details
7. **Risk Emphasis:** ALL critical findings must be highlighted and include risk score + priority
8. **Actionable Recommendations:** Every recommendation needs owner, timeline, effort estimate, and steps
9. **Professional Tone:** Executive summary suitable for C-level review, technical details in analysis sections
10. **Comprehensive Tables:** Every risk assessment section must include a properly formatted comparison table

Generate the complete, detailed, professionally formatted threat assessment report now, following ALL structure and formatting requirements above.
  - **Top 5 Findings** (bulleted, one sentence each).
  - **Top 3 Prioritized Recommendations** (short bullets).
- For each **CRITICAL** or **HIGH** finding include a short **Rationale** paragraph explaining why the finding is scored that way and include at least one authoritative reference (cite sources inline using short bracketed citations, e.g., `[NIST SP 800-53]`, `[OWASP Top 10]`, `[MITRE ATT&CK]`, `[ISO 27001]`).
- At the end of the report include a **REFERENCES** section listing the cited sources with short URLs where possible.
- Use clear markdown headings, tables for matrices, and bullet lists; bold critical findings and label risk levels clearly.

Generate the document in Markdown so it renders well as both Markdown and PDF.
"""

    # Call Claude API
    try:
        # Ensure prompt starts with the required Human turn for Claude
        if not (prompt.startswith("\n\nHuman:") or prompt.startswith("\n\nSystem:") or prompt.startswith("Human:") or prompt.startswith("System:")):
            final_prompt = f"\n\nHuman: {prompt}\n\nAssistant:"
        else:
            final_prompt = prompt

        # Save a short preview of the formatted prompt for debugging (visible only on error)
        try:
            preview = final_prompt[:300]
            # Only store preview if user has enabled prompt debugging
            if getattr(st.session_state, 'prompt_debug_enabled', False):
                setattr(st.session_state, '_debug_prompt_preview', preview)
        except Exception:
            # Non-fatal if session state isn't writable in some test contexts
            # Only store fallback if debugging is conceptually enabled
            if globals().get('PROMPT_DEBUG_ENABLED_FALLBACK', False):
                _debug_prompt_preview = final_prompt[:300]

        # Decide whether to use the Completions API or the Messages API
        model_name = "claude-sonnet-4-20250514"
        prefer_messages_auto = any(prefix in model_name.lower() for prefix in PREFERRED_MESSAGES_API_FAMILIES)
        prefer_messages = getattr(st.session_state, 'force_messages_api', False) or prefer_messages_auto

        # If preferring messages API, call it directly
        if prefer_messages:
            try:
                content = final_prompt
                if content.startswith("\n\nHuman:"):
                    content = content.split("Human:", 1)[1].lstrip()
                elif content.startswith("\n\nSystem:"):
                    content = content.split("System:", 1)[1].lstrip()

                messages = [{"role": "user", "content": content}]

                resp = client.beta.messages.create(
                    model=model_name,
                    messages=messages,
                    max_tokens=16000,
                    temperature=0,
                )

                # Try to extract text content from common response shapes
                def _extract_message_text(resp_obj):
                    # Handle Claude API Message object with content blocks
                    if hasattr(resp_obj, 'content'):
                        content = resp_obj.content
                        # content is a list of ContentBlock objects
                        if isinstance(content, list):
                            text_parts = []
                            for block in content:
                                # Each ContentBlock has a 'text' attribute
                                if hasattr(block, 'text'):
                                    text_parts.append(block.text)
                                elif isinstance(block, dict) and 'text' in block:
                                    text_parts.append(block['text'])
                                elif isinstance(block, str):
                                    text_parts.append(block)
                            if text_parts:
                                return "".join(text_parts)
                        # content might be a string directly
                        elif isinstance(content, str):
                            return content
                    
                    # Check other common attributes
                    for attr in ("message", "output", "completion"):
                        if hasattr(resp_obj, attr):
                            candidate = getattr(resp_obj, attr)
                            # dict-like
                            if isinstance(candidate, dict):
                                # common nested patterns
                                for key in ("text", "content", "parts", "output_text"):
                                    if key in candidate:
                                        val = candidate[key]
                                        if isinstance(val, list):
                                            return "".join(map(str, val))
                                        if isinstance(val, str):
                                            return val
                                # fallback to string
                                return str(candidate)
                            # object-like
                            if isinstance(candidate, str):
                                return candidate
                    
                    # resp_obj might be a dict
                    if isinstance(resp_obj, dict):
                        for key in ("text", "content", "completion", "message"):
                            if key in resp_obj:
                                v = resp_obj[key]
                                if isinstance(v, str):
                                    return v
                                if isinstance(v, list):
                                    return "".join(map(str, v))
                                if isinstance(v, dict):
                                    # nested
                                    for k in ("text", "content"):
                                        if k in v and isinstance(v[k], str):
                                            return v[k]
                    # fallback
                    return str(resp_obj)

                return _extract_message_text(resp)
            except Exception as e_msg:
                # Surface helpful message in the UI
                st.error(f"Error using Messages API: {str(e_msg)}")
                return None

        # Otherwise try the completions API first and fall back to messages if needed
        try:
            completion = client.completions.create(
                model=model_name,
                prompt=final_prompt,
                max_tokens_to_sample=16000,
                temperature=0,
            )

            # The Completion object exposes the generated text on `.completion`
            return getattr(completion, "completion", str(completion))
        except Exception as e_comp:
            # If the model requires the Messages API, fall back and try that
            msg = str(e_comp)
            if "Messages API" in msg or "not supported on this API" in msg or "claude-sonnet" in model_name:
                try:
                    # Convert the final_prompt into a single user message for the Messages API
                    content = final_prompt
                    # strip leading human/system prefixes that were used for the completions endpoint
                    if content.startswith("\n\nHuman:"):
                        content = content.split("Human:", 1)[1].lstrip()
                    elif content.startswith("\n\nSystem:"):
                        content = content.split("System:", 1)[1].lstrip()

                    messages = [{"role": "user", "content": content}]

                    # Use the beta messages API
                    resp = client.beta.messages.create(
                        model=model_name,
                        messages=messages,
                        max_tokens=16000,
                        temperature=0,
                    )

                    # Try to extract text content from common response shapes
                    def _extract_message_text(resp_obj):
                        # Handle Claude API Message object with content blocks
                        if hasattr(resp_obj, 'content'):
                            content = resp_obj.content
                            # content is a list of ContentBlock objects
                            if isinstance(content, list):
                                text_parts = []
                                for block in content:
                                    # Each ContentBlock has a 'text' attribute
                                    if hasattr(block, 'text'):
                                        text_parts.append(block.text)
                                    elif isinstance(block, dict) and 'text' in block:
                                        text_parts.append(block['text'])
                                    elif isinstance(block, str):
                                        text_parts.append(block)
                                if text_parts:
                                    return "".join(text_parts)
                            # content might be a string directly
                            elif isinstance(content, str):
                                return content
                        
                        # Check other common attributes
                        for attr in ("message", "output", "completion"):
                            if hasattr(resp_obj, attr):
                                candidate = getattr(resp_obj, attr)
                                # dict-like
                                if isinstance(candidate, dict):
                                    # common nested patterns
                                    for key in ("text", "content", "parts", "output_text"):
                                        if key in candidate:
                                            val = candidate[key]
                                            if isinstance(val, list):
                                                return "".join(map(str, val))
                                            if isinstance(val, str):
                                                return val
                                    # fallback to string
                                    return str(candidate)
                                # object-like
                                if isinstance(candidate, str):
                                    return candidate
                        
                        # resp_obj might be a dict
                        if isinstance(resp_obj, dict):
                            for key in ("text", "content", "completion", "message"):
                                if key in resp_obj:
                                    v = resp_obj[key]
                                    if isinstance(v, str):
                                        return v
                                    if isinstance(v, list):
                                        return "".join(map(str, v))
                                    if isinstance(v, dict):
                                        # nested
                                        for k in ("text", "content"):
                                            if k in v and isinstance(v[k], str):
                                                return v[k]
                        # fallback
                        return str(resp_obj)

                    return _extract_message_text(resp)
                except Exception as e_msg:
                    # If the fallback fails, raise the original completion error for visibility
                    raise e_comp from e_msg
            # Re-raise if it's not the messages API case
            raise
    except Exception as e:
        # Show the error and include a prompt preview to help diagnose formatting issues
        st.error(f"Error generating threat assessment: {str(e)}")
        preview = getattr(st.session_state, '_debug_prompt_preview', None) if hasattr(st, 'session_state') else None
        if not preview:
            # Fallback if session_state wasn't set
            preview = globals().get('_debug_prompt_preview', None)
        if preview:
            st.error(f"Formatted prompt preview (first 300 chars): {repr(preview)}")
        else:
            st.error("Formatted prompt preview not available")
        return None

def _pdf_support_status():
    """Return (supported: bool, reason: str)."""
    try:
        import markdown as _markdown  # type: ignore
    except Exception as e:
        return False, "missing Python package 'markdown'"
    try:
        from weasyprint import HTML  # type: ignore
    except Exception as e:
        return False, "missing 'weasyprint' or its system dependencies (Cairo/Pango)"
    return True, ""


def check_weasyprint():
    """Lightweight import check for WeasyPrint. Returns (ok: bool, detail: str)."""
    try:
        import weasyprint  # type: ignore
        ver = getattr(weasyprint, '__version__', None)
        if ver:
            return True, f"weasyprint=={ver}"
        return True, "weasyprint imported (version unknown)"
    except Exception as e:
        return False, str(e)


# Preview helpers
def pdf_bytes_to_data_uri(pdf_bytes: bytes) -> str:
    """Return a data URI for embedding PDF bytes in an iframe."""
    b64 = base64.b64encode(pdf_bytes).decode('ascii')
    return f"data:application/pdf;base64,{b64}"


def markdown_to_html(md_text: str) -> str:
    """Convert markdown to HTML using python-markdown (safe fallback if available)."""
    try:
        import markdown as _markdown  # type: ignore
        md = _markdown.Markdown(extensions=["tables", "fenced_code", "toc"])
        html_body = md.convert(md_text or "")
        # Simple wrapper for consistent preview styling
        return f"<div style='font-family: Arial, Helvetica, sans-serif; line-height:1.4; color:#222'>{html_body}</div>"
    except Exception:
        # If python-markdown isn't available, do a very small fallback
        escaped = (md_text or "").replace("<", "&lt;").replace(">", "&gt;")
        return f"<pre style='white-space: pre-wrap;'>{escaped}</pre>"


def clean_markdown_artifacts(html_text):
    """Clean up common markdown artifacts from HTML output."""
    import re
    # Remove literal \n sequences that appear as text
    html_text = html_text.replace('\\n', ' ')
    # Remove markdown link syntax that might not have been converted
    html_text = re.sub(r'\[([^\]]+)\]\(([^)]+)\)', r'<a href="\2">\1</a>', html_text)
    # Clean up double spaces
    html_text = re.sub(r'  +', ' ', html_text)
    return html_text


def apply_risk_styling(html_text):
    """Apply color styling to risk level indicators in HTML."""
    import re
    
    # Style CRITICAL risk levels with red
    html_text = re.sub(
        r'\b(CRITICAL|Critical)\b',
        r'<span class="risk-critical">\1</span>',
        html_text
    )
    
    # Style HIGH risk levels with orange
    html_text = re.sub(
        r'\b(HIGH|High)\b',
        r'<span class="risk-high">\1</span>',
        html_text
    )
    
    # Style MEDIUM risk levels with yellow
    html_text = re.sub(
        r'\b(MEDIUM|Medium)\b',
        r'<span class="risk-medium">\1</span>',
        html_text
    )
    
    # Style LOW risk levels with green
    html_text = re.sub(
        r'\b(LOW|Low)\b',
        r'<span class="risk-low">\1</span>',
        html_text
    )
    
    # Style priority indicators
    html_text = re.sub(
        r'\b(P0)\b',
        r'<span class="priority-critical">\1</span>',
        html_text
    )
    
    html_text = re.sub(
        r'\b(P1)\b',
        r'<span class="priority-high">\1</span>',
        html_text
    )
    
    return html_text


def create_pdf_download(report_content, project_name):
    """Create a PDF download (preferred) and a markdown fallback.

    Tries to render the markdown report to PDF using WeasyPrint. If the
    required packages or system libraries are not available, falls back to
    returning the raw markdown and a `.md` filename. When running in the
    Streamlit app, diagnostic details are stored in `st.session_state['_pdf_error']`.
    """
    base = f"Threat_Assessment_{project_name.replace(' ', '_')}_{datetime.now().strftime('%Y%m%d')}"
    pdf_filename = f"{base}.pdf"
    md_filename = f"{base}.md"

    # Clear previous diagnostic
    try:
        if hasattr(st, 'session_state') and hasattr(st.session_state, '_pdf_error'):
            delattr(st.session_state, '_pdf_error')
    except Exception:
        pass

    # Try to convert markdown -> HTML -> PDF using WeasyPrint (optional dependency)
    try:
        import markdown as _markdown  # optional
        from weasyprint import HTML  # optional

        # Build logo HTML if available
        logo_html = ""
        if st.session_state.logo_image:
            try:
                logo_b64 = base64.b64encode(st.session_state.logo_image).decode()
                logo_html = f'<img src="data:image/png;base64,{logo_b64}" style="max-width: 120px; height: auto;">'
            except Exception:
                pass

        # Use python-markdown with toc extension to generate a Table of Contents
        md = _markdown.Markdown(extensions=["tables", "fenced_code", "toc"])
        html_body = md.convert(report_content or "")
        html_body = clean_markdown_artifacts(html_body)
        html_body = apply_risk_styling(html_body)  # Apply color styling to risk levels
        toc_html = md.toc if hasattr(md, 'toc') else ''
        toc_html = clean_markdown_artifacts(toc_html)

        company_header = st.session_state.company_name or "Threat Assessment"
        footer_text = st.session_state.report_footer or f"Generated {datetime.now().strftime('%Y-%m-%d %H:%M')}"

        full_html = f"""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="utf-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>{company_header} - Threat Assessment</title>
            <style>
                * {{ margin: 0; padding: 0; box-sizing: border-box; }}
                
                /* Page setup */
                @page {{ 
                    size: A4; 
                    margin: 2cm 2cm 2.5cm 2cm;
                    @bottom-left {{ 
                        content: "{footer_text}"; 
                        font-size: 9pt; 
                        color: #666; 
                    }}
                    @bottom-right {{ 
                        content: "Page " counter(page) " of " counter(pages); 
                        font-size: 9pt; 
                        color: #666; 
                    }}
                }}
                @page :first {{ margin-top: 2.5cm; }}
                
                html {{ 
                    width: 100%; 
                }}
                
                body {{ 
                    width: 100%;
                    min-height: 100%;
                    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Roboto', 'Oxygen', 'Ubuntu', sans-serif;
                    font-size: 11pt;
                    line-height: 1.5;
                    color: #1a202c;
                    background: white;
                    padding: 0;
                    margin: 0;
                }}
                
                /* Header section */
                .doc-header {{
                    border-bottom: 3px solid #2d3748;
                    padding: 1.5rem 0;
                    margin-bottom: 2rem;
                    display: flex;
                    justify-content: space-between;
                    align-items: flex-start;
                }}
                
                .logo-section {{ flex: 0 0 auto; }}
                .logo-section img {{ max-width: 100px; height: auto; }}
                
                .title-section {{ 
                    flex: 1; 
                    text-align: center;
                    padding: 0 2rem;
                }}
                
                .title-section h1 {{
                    font-size: 28pt;
                    color: #1a202c;
                    margin: 0 0 0.5rem 0;
                    font-weight: 700;
                }}
                
                .title-section p {{
                    font-size: 12pt;
                    color: #666;
                    margin: 0;
                }}
                
                .date-section {{
                    flex: 0 0 auto;
                    text-align: right;
                    font-size: 10pt;
                    color: #666;
                }}
                
                /* Table of Contents */
                .toc-container {{
                    background: #f7fafc;
                    border-left: 4px solid #2d3748;
                    padding: 1.5rem;
                    margin: 2rem 0;
                    page-break-inside: avoid;
                    border-radius: 4px;
                }}
                
                .toc-container h2 {{
                    font-size: 14pt;
                    margin: 0 0 1rem 0;
                    color: #1a202c;
                }}
                
                .toc-container ul {{
                    list-style: none;
                    padding: 0;
                    margin: 0;
                }}
                
                .toc-container li {{
                    margin: 0.4rem 0;
                    padding-left: 1.5rem;
                }}
                
                .toc-container a {{
                    color: #2c5282;
                    text-decoration: none;
                    font-size: 10pt;
                }}
                
                /* Main content */
                main {{
                    padding: 0;
                }}
                
                /* Headings with page break control */
                h1 {{ 
                    font-size: 22pt;
                    color: #1a202c;
                    margin: 3rem 0 1.5rem 0;
                    padding: 0.8rem 0 0.5rem 0;
                    border-bottom: 3px solid #2d3748;
                    page-break-before: always;
                    page-break-after: avoid;
                    font-weight: 700;
                    letter-spacing: 0.5px;
                }}
                
                h1:first-of-type {{
                    page-break-before: avoid;
                    margin-top: 0;
                }}
                
                h2 {{ 
                    font-size: 16pt;
                    color: #2d3748;
                    margin: 2.2rem 0 1rem 0;
                    padding-top: 0.8rem;
                    padding-bottom: 0.3rem;
                    border-bottom: 2px solid #cbd5e0;
                    page-break-after: avoid;
                    font-weight: 700;
                }}
                
                h3 {{ 
                    font-size: 13pt;
                    color: #2c5282;
                    margin: 1.5rem 0 0.8rem 0;
                    padding-top: 0.5rem;
                    page-break-after: avoid;
                    font-weight: 700;
                }}
                
                h4 {{ 
                    font-size: 11.5pt;
                    color: #4a5568;
                    margin: 1.2rem 0 0.6rem 0;
                    page-break-after: avoid;
                    font-weight: 600;
                }}
                
                h5, h6 {{
                    font-size: 10.5pt;
                    color: #4a5568;
                    margin: 1rem 0 0.5rem 0;
                    page-break-after: avoid;
                    font-weight: 600;
                }}
                
                /* Paragraphs with proper spacing */
                p {{
                    margin: 1rem 0;
                    text-align: justify;
                    line-height: 1.6;
                    orphans: 3;
                    widows: 3;
                }}
                
                /* Lists with proper spacing */
                ul, ol {{
                    margin: 1.2rem 0;
                    padding-left: 2.2rem;
                }}
                
                li {{
                    margin: 0.6rem 0;
                    padding-left: 0.4rem;
                    line-height: 1.5;
                }}
                
                ul ul, ol ol, ul ol, ol ul {{
                    margin: 0.6rem 0;
                    padding-left: 2rem;
                }}
                
                /* Tables with professional styling */
                table {{
                    width: 100%;
                    max-width: 100%;
                    border-collapse: collapse;
                    margin: 1.6rem 0;
                    page-break-inside: auto;
                    font-size: 8pt;
                    background: white;
                    table-layout: fixed;
                }}
                
                table tr {{
                    page-break-inside: avoid;
                    page-break-after: auto;
                }}
                
                table, th, td {{
                    border: 1px solid #cbd5e0;
                }}
                
                th {{
                    background: #2d3748;
                    color: white;
                    padding: 0.55rem 0.5rem;
                    text-align: left;
                    font-weight: 700;
                    font-size: 8pt;
                    word-wrap: break-word;
                    overflow-wrap: anywhere;
                    max-width: 110px;
                }}
                
                td {{
                    padding: 0.45rem 0.55rem;
                    vertical-align: top;
                    line-height: 1.35;
                    word-wrap: break-word;
                    overflow-wrap: anywhere;
                    max-width: 110px;
                }}
                
                tbody tr:nth-child(odd) {{ 
                    background: #f7fafc; 
                }}
                
                tbody tr:nth-child(even) {{
                    background: white;
                }}
                
                tbody tr:hover {{
                    background: #edf2f7;
                }}
                
                /* Risk level styling in tables */
                td:contains('CRITICAL'), 
                td:contains('Critical') {{
                    color: #c53030;
                    font-weight: 700;
                }}
                
                td:contains('HIGH'),
                td:contains('High') {{
                    color: #d97706;
                    font-weight: 700;
                }}
                
                td:contains('MEDIUM'),
                td:contains('Medium') {{
                    color: #d69e2e;
                    font-weight: 700;
                }}
                
                td:contains('LOW'),
                td:contains('Low') {{
                    color: #22543d;
                    font-weight: 600;
                }}
                
                /* Code blocks with better styling */
                pre {{
                    background: #1e293b;
                    color: #e2e8f0;
                    padding: 1.2rem;
                    border-radius: 5px;
                    margin: 1.5rem 0;
                    overflow-x: auto;
                    page-break-inside: avoid;
                    font-size: 8.5pt;
                    line-height: 1.5;
                    font-family: 'Courier New', 'Consolas', monospace;
                    white-space: pre-wrap;
                    word-wrap: break-word;
                    border-left: 4px solid #3b82f6;
                }}
                
                pre code {{
                    background: none;
                    color: #e2e8f0;
                    padding: 0;
                    border-radius: 0;
                    font-size: 8.5pt;
                    font-weight: 400;
                }}
                
                code {{
                    background: #f1f5f9;
                    color: #d97706;
                    padding: 2px 6px;
                    border-radius: 3px;
                    font-family: 'Courier New', 'Consolas', monospace;
                    font-size: 9pt;
                    font-weight: 500;
                }}
                
                /* Risk levels and emphasis */
                strong, b {{
                    font-weight: 700;
                    color: #1a202c;
                }}
                
                em, i {{
                    font-style: italic;
                    color: #4a5568;
                }}
                
                /* Risk level styling with color-coding */
                .risk-critical {{
                    color: #c53030;
                    font-weight: 700;
                    background: #fdf2f2;
                    padding: 2px 6px;
                    border-radius: 3px;
                }}
                
                .risk-high {{
                    color: #d97706;
                    font-weight: 700;
                    background: #fffbf0;
                    padding: 2px 6px;
                    border-radius: 3px;
                }}
                
                .risk-medium {{
                    color: #d69e2e;
                    font-weight: 700;
                    background: #fffaf0;
                    padding: 2px 6px;
                    border-radius: 3px;
                }}
                
                .risk-low {{
                    color: #22543d;
                    font-weight: 600;
                    background: #f0fdf4;
                    padding: 2px 6px;
                    border-radius: 3px;
                }}
                
                /* Priority styling */
                .priority-critical {{
                    color: #c53030;
                    font-weight: 700;
                    background: #fdf2f2;
                    padding: 2px 6px;
                    border-radius: 3px;
                }}
                
                .priority-high {{
                    color: #d97706;
                    font-weight: 700;
                    background: #fffbf0;
                    padding: 2px 6px;
                    border-radius: 3px;
                }}
                
                /* Finding boxes */
                .finding-critical {{
                    border-left: 5px solid #c53030;
                    background: #fdf2f2;
                    padding: 1rem;
                    margin: 1.5rem 0;
                    page-break-inside: avoid;
                    border-radius: 3px;
                }}
                
                .finding-high {{
                    border-left: 5px solid #d97706;
                    background: #fffbf0;
                    padding: 1rem;
                    margin: 1.5rem 0;
                    page-break-inside: avoid;
                    border-radius: 3px;
                }}
                
                /* Important pointers */
                .important {{
                    background: #fffaf0;
                    border-left: 4px solid #d69e2e;
                    padding: 0.8rem;
                    margin: 1rem 0;
                    page-break-inside: avoid;
                    font-size: 10pt;
                }}
                
                /* Section dividers */
                hr {{
                    border: none;
                    border-top: 2px solid #cbd5e0;
                    margin: 2.5rem 0;
                    page-break-after: avoid;
                }}
                
                /* Blockquotes */
                blockquote {{
                    border-left: 4px solid #cbd5e0;
                    padding-left: 1rem;
                    margin: 1.5rem 0;
                    padding: 0.8rem 1rem;
                    color: #4a5568;
                    background: #f7fafc;
                    page-break-inside: avoid;
                    font-style: italic;
                }}
                
                /* Links */
                a {{
                    color: #2c5282;
                    text-decoration: none;
                    page-break-inside: avoid;
                }}
                
                a:hover {{
                    text-decoration: underline;
                }}
                
                /* Horizontal rule */
                hr {{
                    border: none;
                    border-top: 1px solid #e2e8f0;
                    margin: 2rem 0;
                    page-break-after: avoid;
                }}
                
                /* Page breaks */
                .page-break {{
                    page-break-before: always;
                }}
                
                /* Ensure proper spacing */
                main > *:first-child {{
                    margin-top: 0;
                }}
            </style>
        </head>
        <body>
        <div class="doc-header">
            <div class="logo-section">{logo_html}</div>
            <div class="title-section">
                <h1>{company_header}</h1>
                <p>Enterprise Threat Assessment Report</p>
            </div>
            <div class="date-section">
                <p>Report Date</p>
                <p>{datetime.now().strftime('%B %d, %Y')}</p>
            </div>
        </div>
        
        <div class="toc-container">
            <h2>Contents</h2>
            {toc_html}
        </div>
        
        <main>{html_body}</main>
        </body>
        </html>
        """

        # Generate PDF with full content rendering (no truncation)
        pdf_bytes = HTML(string=full_html).write_pdf(
            presentational_hints=True,
            optimize_size=('fonts',)  # Optimize fonts but keep full content
        )
        return pdf_filename, pdf_bytes, "application/pdf"
    except Exception as e:
        # Store diagnostic info for UI visibility if possible
        try:
            if hasattr(st, 'session_state'):
                setattr(st.session_state, '_pdf_error', str(e))
        except Exception:
            pass

        # Fallback: attempt a styled PDF using ReportLab so the button still appears
        try:
            from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
            from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
            from reportlab.lib.pagesizes import A4
            from reportlab.lib.units import cm
            from reportlab.lib import colors
            from bs4 import BeautifulSoup

            buffer = io.BytesIO()
            doc = SimpleDocTemplate(
                buffer,
                pagesize=A4,
                leftMargin=2*cm,
                rightMargin=2*cm,
                topMargin=2*cm,
                bottomMargin=2*cm,
            )
            styles = getSampleStyleSheet()
            styles.add(ParagraphStyle(name='H1', fontSize=18, leading=22, spaceAfter=10, spaceBefore=10))
            styles.add(ParagraphStyle(name='H2', fontSize=14, leading=18, spaceAfter=8, spaceBefore=8))
            styles.add(ParagraphStyle(name='H3', fontSize=12, leading=16, spaceAfter=6, spaceBefore=6))
            header_style = ParagraphStyle(
                name='TableHeader',
                parent=styles['BodyText'],
                fontName='Helvetica-Bold',
                textColor=colors.white,
                fontSize=8,
                leading=10
            )
            story = []

            # Title
            header_text = getattr(st.session_state, 'company_name', None) or "Threat Assessment"
            story.append(Paragraph(f"{header_text} - Threat Assessment", styles['Title']))
            story.append(Spacer(1, 12))

            # Convert markdown to HTML and parse
            try:
                import markdown as _markdown
                md = _markdown.Markdown(extensions=["tables", "fenced_code", "toc"])
                html = md.convert(report_content or "")
            except Exception:
                html = f"<pre>{(report_content or '').replace('<','&lt;').replace('>','&gt;')}</pre>"

            soup = BeautifulSoup(html, 'html.parser')

            def colorize_text(text: str) -> str:
                # Apply risk color spans recognized by ReportLab (<font color="...">)
                rep = (
                    ('CRITICAL', 'c53030'), ('Critical', 'c53030'),
                    ('HIGH', 'd97706'), ('High', 'd97706'),
                    ('MEDIUM', 'd69e2e'), ('Medium', 'd69e2e'),
                    ('LOW', '22543d'), ('Low', '22543d'),
                )
                for key, col in rep:
                    text = text.replace(key, f'<font color="#{col}"><b>{key}</b></font>')
                return text

            def add_table(table_tag):
                rows = []
                for tr in table_tag.find_all('tr'):
                    cells = []
                    for cell in tr.find_all(['th', 'td']):
                        cell_text = colorize_text(cell.get_text(" ", strip=True))
                        cell_style = header_style if cell.name == 'th' else styles['BodyText']
                        cells.append(Paragraph(cell_text or " ", cell_style))
                    rows.append(cells)
                if not rows:
                    return
                tbl = Table(rows, repeatRows=1)
                style_cmds = [
                    ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#cbd5e0')),
                    ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#2d3748')),
                    ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0,0), (-1,-1), 8),
                    ('VALIGN', (0,0), (-1,-1), 'TOP'),
                ]
                # Zebra stripes for body
                for i in range(1, len(rows)):
                    bg = colors.HexColor('#f7fafc') if i % 2 == 1 else colors.white
                    style_cmds.append(('BACKGROUND', (0,i), (-1,i), bg))
                tbl.setStyle(TableStyle(style_cmds))
                story.append(tbl)
                story.append(Spacer(1, 10))

            # Walk top-level elements and render
            for el in soup.contents:
                name = getattr(el, 'name', None)
                if not name:
                    # Text node
                    txt = str(el).strip()
                    if txt:
                        story.append(Paragraph(colorize_text(txt), styles['BodyText']))
                        story.append(Spacer(1, 6))
                    continue

                if name in ('h1', 'h2', 'h3'):
                    style = styles['H1'] if name == 'h1' else styles['H2'] if name == 'h2' else styles['H3']
                    story.append(Paragraph(colorize_text(el.get_text()), style))
                    story.append(Spacer(1, 6))
                elif name == 'p':
                    story.append(Paragraph(colorize_text(el.decode_contents()), styles['BodyText']))
                    story.append(Spacer(1, 6))
                elif name == 'table':
                    add_table(el)
                else:
                    # Fallback for other tags
                    story.append(Paragraph(colorize_text(el.get_text()), styles['BodyText']))
                    story.append(Spacer(1, 6))

            doc.build(story)
            pdf_bytes = buffer.getvalue()
            return pdf_filename, pdf_bytes, "application/pdf"
        except Exception:
            # If ReportLab fallback also fails, return the markdown as a final fallback
            return md_filename, report_content, "text/markdown"


def render_markdown_as_html(markdown_text):
    """Convert markdown to HTML for in-app preview."""
    try:
        import markdown as _markdown  # optional
        md = _markdown.Markdown(extensions=["tables", "fenced_code", "toc"])
        html = md.convert(markdown_text or "")
        return html
    except Exception:
        # Fallback: wrap in pre tag if markdown conversion fails
        return f"<pre>{markdown_text}</pre>"


def show_report_preview(report_content, is_pdf_available=False):
    """Display an in-app preview of the report (HTML-rendered)."""
    with st.container():
        st.markdown("### 📖 Report Preview")
        
        if is_pdf_available:
            preview_note = "✅ PDF is available below. Click to download or preview below."
        else:
            preview_note = "📄 PDF is not available. Here's an HTML preview of your report:"
        
        st.info(preview_note)
        
        # Render the markdown as HTML for preview
        html_content = render_markdown_as_html(report_content)
        
        st.markdown(f'<div class="report-preview">{html_content}</div>', unsafe_allow_html=True)


def main():
    # Header
    st.markdown("""
        <div style='text-align: center; padding: 2rem 0;'>
            <h1>🔒 AI-Powered Threat Modeling Tool</h1>
            <p class='header-subtitle'>Enterprise-grade threat assessment powered by SecureAI</p>
        </div>
    """, unsafe_allow_html=True)
    
    # Sidebar
    with st.sidebar:
        st.markdown("### ⚙️ Configuration")
        
        # API Key input (prefill from Streamlit secrets or environment for deployments)
        default_api_key = ""
        try:
            if hasattr(st, 'secrets') and 'SECUREAI_API_KEY' in st.secrets:
                default_api_key = st.secrets['SECUREAI_API_KEY'] or ""
        except Exception:
            pass
        if not default_api_key:
            default_api_key = os.environ.get('SECUREAI_API_KEY', "")

        api_key = st.text_input(
            "SecureAI API Key",
            type="password",
            value=default_api_key,
            help="Enter your SecureAI API key to enable threat assessment (or set SECUREAI_API_KEY in Streamlit secrets/env)"
        )
        
        if api_key:
            st.success("✓ API Key configured")
        else:
            st.warning("⚠️ Please enter your API key to continue")

        st.markdown("---")
        
        # Branding & Customization
        st.markdown("### 🎨 Branding & Customization")
        
        logo_file = st.file_uploader(
            "Upload Company Logo (PDF/PNG/JPG)",
            type=['png', 'jpg', 'jpeg', 'gif'],
            help="Logo will appear in PDF header"
        )
        if logo_file:
            st.session_state.logo_image = logo_file.read()
            st.success("✓ Logo uploaded")
        
        st.session_state.company_name = st.text_input(
            "Company/Project Name",
            value=st.session_state.company_name,
            placeholder="Your Company",
            help="Appears in PDF header and title"
        )
        
        st.session_state.report_footer = st.text_input(
            "Report Footer Text",
            value=st.session_state.report_footer,
            placeholder="e.g., Confidential - For Authorized Use Only",
            help="Appears at bottom of each PDF page"
        )

        st.markdown("---")

        # PDF availability indicator
        pdf_supported, pdf_reason = _pdf_support_status()
        if pdf_supported:
            st.success("PDF export: available (weasyprint & markdown detected)")
        else:
            st.warning(f"PDF export: not available — {pdf_reason}. See installation guidance in the docs.")

        # Quick WeasyPrint diagnostic
        if st.button("🔍 Check WeasyPrint"):
            ok, detail = check_weasyprint()
            try:
                st.session_state['_weasycheck'] = {"ok": ok, "detail": detail}
            except Exception:
                pass
            if ok:
                st.success(f"WeasyPrint OK — {detail}")
            else:
                st.error(f"WeasyPrint check failed: {detail}")
                st.markdown("**Helpful links:**")
                st.markdown("- https://doc.courtbouillon.org/weasyprint/stable/first_steps.html#installation")
                st.markdown("- https://doc.courtbouillon.org/weasyprint/stable/first_steps.html#troubleshooting")
                st.text_area("Copy diagnostic (include this text when filing an issue):", value=f"WeasyPrint check failed: {detail}", height=140, key='weasy_diag')

        # If a check was done previously, show summary
        weasy_prev = getattr(st.session_state, '_weasycheck', None) if hasattr(st, 'session_state') else None
        if weasy_prev:
            if weasy_prev.get('ok'):
                st.info(f"Last WeasyPrint check: OK — {weasy_prev.get('detail')}")
            else:
                st.warning(f"Last WeasyPrint check: FAILED — {weasy_prev.get('detail')}")
                st.markdown("See installation docs for troubleshooting: https://doc.courtbouillon.org/weasyprint/stable/first_steps.html#troubleshooting")

        # Toggle to enable prompt debugging (only when troubleshooting)
        st.checkbox(
            "Enable prompt debugging (show prompt preview on API errors)",
            value=False,
            help="When enabled, the first 300 characters of the formatted prompt will be shown when the SecureAI API returns an error. Do NOT enable when uploading sensitive documents.",
            key="prompt_debug_enabled"
        )

        # Optionally force use of the Messages API (override auto-detection)
        st.checkbox(
            "Force use of Messages API (override auto-detection)",
            value=False,
            help="When enabled, the app will use the Messages API instead of the Completions API regardless of model family detection. Use for debugging or compatibility testing.",
            key="force_messages_api"
        )
        
        st.markdown("---")
        
        # Navigation
        st.markdown("### 📋 Quick Navigation")
        st.markdown("""
        - [Project Setup](#project-information)
        - [Upload Documents](#upload-project-documents)
        - [Select Framework](#select-threat-modeling-framework)
        - [Risk Areas](#select-risk-focus-areas)
        - [Generate Report](#generate-threat-assessment)
        """)
        
        st.markdown("---")
        
        # Help
        st.markdown("### 💡 Help")
        with st.expander("How to use this tool"):
            st.markdown("""
            1. **Enter API Key:** Add your SecureAI API key
            2. **Project Info:** Fill in project details
            3. **Upload Documents:** Add architecture diagrams, design docs, etc.
            4. **Select Framework:** Choose your threat modeling approach
            5. **Select Risks:** Pick specific risk areas to assess
            6. **Generate:** Click to create your threat assessment
            7. **Download:** Get your PDF report
            """)
        
        with st.expander("Supported Documents"):
            st.markdown("""
            - Architecture Diagrams (PNG, JPG, PDF)
            - Design Documents (PDF, DOCX, TXT, MD)
            - Network Diagrams (PNG, JPG, PDF)
            - Data Flow Diagrams (PNG, JPG, PDF)
            - API Specifications (YAML, JSON, MD)
            - Technical Documentation (PDF, MD, TXT)
            """)
    
    # Main content
    if not api_key:
        st.info("👈 Please enter your SecureAI API key in the sidebar to get started")
        st.markdown("""
        ### Get Your API Key
        1. Visit [SecureAI Console](https://console.anthropic.com/)
        2. Create an account or sign in
        3. Generate an API key
        4. Paste it in the sidebar
        """)
        return
    
    # Top Navigation Bar with Reset Button
    col_header_1, col_header_2, col_header_3 = st.columns([3, 1, 1])
    
    with col_header_1:
        st.markdown("# 🛡️ AI Threat Modeling Tool")
        st.markdown('<p class="header-subtitle">Enterprise-grade threat assessment powered by SecureAI</p>', unsafe_allow_html=True)
    
    with col_header_3:
        if st.session_state.assessment_complete:
            if st.button("🔄 Clear Assessment", key="reset_btn", use_container_width=True):
                st.session_state.show_reset_confirm = True
            
            if st.session_state.show_reset_confirm:
                st.warning("⚠️ This will clear all fields and the current assessment. Continue?")
                col_confirm1, col_confirm2 = st.columns(2)
                with col_confirm1:
                    if st.button("✓ Yes, Clear All", key="confirm_reset", use_container_width=True):
                        reset_assessment_form()
                        st.rerun()
                with col_confirm2:
                    if st.button("✗ Cancel", key="cancel_reset", use_container_width=True):
                        st.session_state.show_reset_confirm = False
                        st.rerun()
    
    st.markdown("---")
    
    # Project Information
    st.markdown("## 📊 Project Information")
    
    col1, col2 = st.columns(2)
    
    with col1:
        project_name = st.text_input(
            "Project Name *",
            placeholder="e.g., Customer Portal Application",
            help="Enter the name of the project to assess"
        )
        
        app_type = st.selectbox(
            "Application Type *",
            ["Web Application", "Mobile Application", "API/Microservice", 
             "Desktop Application", "Cloud Service", "IoT System", "AI/ML Platform"]
        )
        
        deployment = st.selectbox(
            "Deployment Model *",
            ["Cloud (AWS)", "Cloud (Azure)", "Cloud (GCP)", "Cloud (Multi-Cloud)",
             "On-Premises", "Hybrid", "Edge Computing"]
        )
    
    with col2:
        criticality = st.selectbox(
            "Business Criticality *",
            ["Critical", "High", "Medium", "Low"],
            help="Impact if this system is compromised"
        )
        
        compliance = st.multiselect(
            "Compliance Requirements",
            ["PCI-DSS", "GDPR", "HIPAA", "SOX", "ISO 27001", "SOC 2", 
             "NIST", "FedRAMP", "APRA CPS 234"],
            help="Select all applicable compliance requirements"
        )
        
        environment = st.selectbox(
            "Environment",
            ["Production", "Staging", "Development", "UAT", "DR/Backup"]
        )
    
    # Upload Documents
    st.markdown("## 📁 Upload Project Documents")
    
    st.markdown("""
        <div class='upload-box'>
            <h3>📤 Drop your files here</h3>
            <p style='margin: 0.5rem 0; color: #666;'>Supported: PDF, DOCX, TXT, MD, PNG, JPG, YAML, JSON</p>
            <p style='margin: 0.5rem 0; font-size: 0.9rem; color: #999;'>Architecture diagrams, design docs, data flows, API specs, technical documentation</p>
        </div>
    """, unsafe_allow_html=True)
    
    uploaded_files = st.file_uploader(
        "Choose files",
        accept_multiple_files=True,
        type=['pdf', 'docx', 'txt', 'md', 'png', 'jpg', 'jpeg', 'yaml', 'json'],
        help="Upload architecture diagrams, design documents, data flow diagrams, etc.",
        label_visibility="collapsed"
    )
    
    if uploaded_files:
        st.success(f"✓ {len(uploaded_files)} file(s) uploaded - Ready for analysis")
        
        # Show uploaded files with better styling
        with st.expander("📋 Uploaded Files Summary", expanded=True):
            total_size = sum(f.size for f in uploaded_files) / 1024 / 1024
            st.metric("Total Files", len(uploaded_files), delta="Ready for processing")
            
            for idx, file in enumerate(uploaded_files, 1):
                col1, col2, col3, col4 = st.columns([3, 1.5, 1.2, 0.5])
                with col1:
                    st.markdown(f"**{idx}. {file.name}**")
                with col2:
                    st.markdown(f"`{file.size / 1024:.1f} KB`")
                with col3:
                    st.markdown(f"*{Path(file.name).suffix.upper()[1:]}*")
                with col4:
                    st.markdown("✓")
            
            if total_size > 0:
                st.caption(f"📊 Total size: {total_size:.2f} MB")
    else:
        st.info("👆 Upload documents to enable threat assessment generation")
    
    # Select Threat Modeling Framework
    st.markdown("## 🎯 Select Threat Modeling Framework")
    
    st.markdown('<p style="color: #666; margin-bottom: 1rem;">Choose the framework that best fits your threat modeling needs</p>', unsafe_allow_html=True)
    
    framework_cols = st.columns(2)
    
    selected_framework = None
    
    for idx, (framework, details) in enumerate(FRAMEWORKS.items()):
        col = framework_cols[idx % 2]
        
        with col:
            is_selected = st.checkbox(
                framework,
                key=f"framework_{framework}",
                help=details['description']
            )
            
            if is_selected:
                selected_framework = framework
                
                st.markdown(f"""
                <div class='framework-card selected'>
                    <h4>{framework}</h4>
                    <p><strong>Focus:</strong> {details['focus']}</p>
                    <p><strong>Best For:</strong> {details['best_for']}</p>
                    <details>
                        <summary><strong>Coverage Areas</strong></summary>
                        <ul>
                            {''.join([f'<li>{area}</li>' for area in details['coverage']])}
                        </ul>
                    </details>
                </div>
                """, unsafe_allow_html=True)
            else:
                st.markdown(f"""
                <div class='framework-card'>
                    <h4>{framework}</h4>
                    <p>{details['description'][:100]}...</p>
                </div>
                """, unsafe_allow_html=True)
    
    # Select Risk Focus Areas
    st.markdown("## 🎲 Select Risk Focus Areas")
    
    st.markdown('<p style="color: #666; margin-bottom: 1rem;">Choose specific risk areas for detailed analysis in the final report</p>', unsafe_allow_html=True)
    
    selected_risks = []
    
    risk_cols = st.columns(2)
    
    for idx, (risk_area, details) in enumerate(RISK_AREAS.items()):
        col = risk_cols[idx % 2]
        
        with col:
            is_selected = st.checkbox(
                risk_area,
                value=True,  # Selected by default
                key=f"risk_{risk_area}",
                help=details['description']
            )
            
            if is_selected:
                selected_risks.append(risk_area)
                
                with st.expander(f"📋 Threats covered in {risk_area}"):
                    for threat in details['threats']:
                        st.markdown(f"- {threat}")
    
    # Generate Assessment
    st.markdown("## 🚀 Generate Threat Assessment")
    
    # Validation
    can_generate = (
        project_name and 
        selected_framework and 
        len(selected_risks) > 0 and
        uploaded_files
    )
    
    if not can_generate:
        missing = []
        if not project_name:
            missing.append("✗ Project Name")
        if not selected_framework:
            missing.append("✗ Threat Modeling Framework")
        if len(selected_risks) == 0:
            missing.append("✗ At least one Risk Focus Area")
        if not uploaded_files:
            missing.append("✗ Project Documents")
        
        st.warning(f"""
        ⚠️ **Complete the following to generate assessment:**
        
        {chr(10).join(f'- {item}' for item in missing)}
        """)
    else:
        st.success("✓ All required fields completed - Ready to generate assessment!")
    
    col1, col2, col3 = st.columns([1, 1.5, 1])
    
    with col2:
        if st.button(
            "🎯 Generate Threat Assessment Report",
            disabled=not can_generate,
            use_container_width=True,
            key="generate_report_btn"
        ):
            st.session_state.processing = True
            
            # Progress tracking
            progress_bar = st.progress(0)
            status_text = st.empty()
            status_container = st.container()
            
            try:
                # Step 1: Process documents
                with status_container:
                    status_text.text("📄 Processing uploaded documents...")
                progress_bar.progress(20)
                
                documents_content = ""
                for file in uploaded_files:
                    content = extract_text_from_file(file)
                    documents_content += f"\n\n### {file.name}\n{content}"
                
                # Step 2: Prepare project info
                with status_container:
                    status_text.text("📊 Preparing project information...")
                progress_bar.progress(40)
                
                project_info = {
                    'name': project_name,
                    'app_type': app_type,
                    'deployment': deployment,
                    'criticality': criticality,
                    'compliance': compliance if compliance else ['None specified'],
                    'environment': environment
                }
                
                # Step 3: Generate assessment
                with status_container:
                    status_text.text("🤖 Generating threat assessment with SecureAI...")
                progress_bar.progress(60)
                
                threat_report = generate_threat_assessment(
                    project_info,
                    documents_content,
                    selected_framework,
                    selected_risks,
                    api_key
                )

                # Augment references automatically when possible
                if threat_report:
                    try:
                        suggestions = _suggest_references_from_text(threat_report)
                        threat_report = _merge_references_section(threat_report, suggestions)
                    except Exception:
                        # Non-fatal if augmentation errors
                        pass

                    progress_bar.progress(100)
                    with status_container:
                        status_text.text("✅ Assessment complete! Generating PDF...")

                    st.session_state.threat_report = threat_report
                    st.session_state.assessment_complete = True
                    st.session_state.processing = False

                    # Clear any stored prompt preview to avoid leaving sensitive data in session state
                    try:
                        if hasattr(st.session_state, '_debug_prompt_preview'):
                            delattr(st.session_state, '_debug_prompt_preview')
                    except Exception:
                        pass

                    st.balloons()
                    st.success("🎉 Threat assessment generated successfully! Download your report below.")
                else:
                    st.error("❌ Failed to generate assessment. Please try again.")
                    st.session_state.processing = False
                    
            except Exception as e:
                st.error(f"❌ Error: {str(e)}")
                st.session_state.processing = False
    
    # Display Results
    if st.session_state.assessment_complete and st.session_state.threat_report:
        st.markdown("---")
        st.markdown("## 📋 Threat Assessment Report")
        st.markdown(f"<p style='color: #666; margin-bottom: 1rem;'><strong>Project:</strong> {project_name} | <strong>Framework:</strong> {selected_framework} | <strong>Risk Level:</strong> {criticality}</p>", unsafe_allow_html=True)
        
        # Download buttons
        col1, col2, col3 = st.columns([1.2, 1.2, 0.6])
        
        with col1:
            filename, content, mime = create_pdf_download(
                st.session_state.threat_report,
                project_name
            )

            if mime == "application/pdf":
                # PDF generated successfully
                st.download_button(
                    label="📥 Download as PDF",
                    data=content,
                    file_name=filename,
                    mime=mime,
                    use_container_width=True
                )
                # If WeasyPrint failed and we used the fallback, surface that clearly
                pdf_err = getattr(st.session_state, '_pdf_error', None) if hasattr(st, 'session_state') else None
                if pdf_err:
                    st.warning(
                        "Using basic PDF fallback (reduced styling). "
                        "For the fully formatted PDF, install WeasyPrint system dependencies or use the Cloud deploy."
                    )
                    with st.expander("Show PDF engine diagnostics"):
                        st.code(str(pdf_err))

        with col2:
            # Also offer the markdown version
            md_filename = filename.rsplit('.', 1)[0] + ".md"
            st.download_button(
                label="📄 Download as Markdown",
                data=st.session_state.threat_report,
                file_name=md_filename,
                mime="text/markdown",
                use_container_width=True
            )
        
        with col3:
            if st.button("📋 Copy to Clipboard", use_container_width=True):
                st.info("✓ Report copied! (Right-click to paste)")
        
        st.markdown("---")
        st.markdown("### Report Preview")
        
        # Display report in expandable sections for better readability
        st.markdown(f"""
        <div class='report-preview'>
            <strong>📊 Assessment Details</strong><br>
            <small>Framework: {selected_framework} | Risk Areas: {', '.join(selected_risks[:3])}{'...' if len(selected_risks) > 3 else ''}</small>
        </div>
        """, unsafe_allow_html=True)
        
        # Show report content in a scrollable container
        with st.expander("📖 Full Report Content", expanded=True):
            st.markdown(st.session_state.threat_report)
            
    elif not st.session_state.threat_report and st.session_state.assessment_complete:
        st.warning("⚠️ Assessment failed to generate. Please check your API key and try again.")


if __name__ == "__main__":
    main()

