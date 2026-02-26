"""
Threat Modeling Frameworks and Risk Assessment Definitions
Complete framework definitions from the original application
"""

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
    },
    "Custom Client Framework": {
        "description": "Your organization's proprietary security assessment framework",
        "focus": "Tailored controls and risk categories specific to your industry",
        "best_for": "Organization-specific compliance, industry regulations, custom security requirements",
        "coverage": ["Custom Domain 1", "Custom Domain 2", "Custom Domain 3", "Industry-Specific Controls"]
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
    },
    "Privacy Risk": {
        "description": "Risks related to personal data protection and privacy",
        "threats": [
            "PII exposure and leakage",
            "Inadequate consent management",
            "Data subject rights violations",
            "Cross-border data transfer issues",
            "Insufficient privacy by design",
            "Third-party data sharing risks",
            "Privacy policy non-compliance"
        ]
    },
    "Supply Chain Risk": {
        "description": "Risks in software supply chain and third-party dependencies",
        "threats": [
            "Compromised dependencies and libraries",
            "Malicious packages and backdoors",
            "Vulnerable third-party components",
            "Insufficient vendor security assessment",
            "Open source license violations",
            "Dependency confusion attacks",
            "Supply chain integrity verification gaps",
            "Third-party service provider risks"
        ]
    },
    "Identity & Access Risk": {
        "description": "Risks related to authentication, authorization, and identity management",
        "threats": [
            "Weak authentication mechanisms",
            "Insufficient access controls",
            "Privilege escalation vulnerabilities",
            "Identity federation weaknesses",
            "Session management flaws",
            "Credential theft and stuffing",
            "Insufficient multi-factor authentication",
            "Role-based access control gaps"
        ]
    }
}


def build_comprehensive_prompt(project_info: dict, documents_content: str, frameworks: list, risk_areas: list, assessment_date: str) -> str:
    """
    Build the comprehensive threat assessment prompt using the original logic
    This is the EXACT prompt that produced perfect results
    """
    
    # Join multiple frameworks
    frameworks_str = " + ".join(frameworks) if len(frameworks) > 1 else frameworks[0]
    framework_descriptions = "\n".join([
        f"**{fw}** - {FRAMEWORKS[fw]['description']}\n  Focus: {FRAMEWORKS[fw]['focus']}\n  Coverage: {', '.join(FRAMEWORKS[fw]['coverage'][:3])}..."
        for fw in frameworks
    ])
    
    # Risk areas descriptions
    risk_areas_details = "\n".join([
        f"- {area}: {RISK_AREAS[area]['description']}"
        for area in risk_areas
    ])
    
    # Risk areas specialized sections
    risk_areas_sections = "\n".join([
        f'''## {area}

**Summary:** [1-2 sentences describing the risk landscape for {area} based on the documentation review]

| Threat ID | Evidence Source (Doc) | Example from Docs | Threat | Likelihood | Impact | Risk Priority | Mitigation Strategy |
|-----------|-----------------------|-------------------|--------|-----------|--------|---------------|---------------------|
| T-{area[:3].upper()}-001 | [Doc: Section] | [Specific example] | [specific threat] | [1-5] | [1-5] | P0/P1/P2 | [specific action] |
'''
        for area in risk_areas
    ])
    
    # Compliance sections
    compliance_rows = "\n".join([
        f"| [F-ID] | [finding] | {req} | [gap description] | [evidence needed] | [timeline] |"
        for req in project_info.get('compliance', [])
    ])
    
    # Framework references
    framework_refs = "\n".join([
        f"- **{fw}** - {FRAMEWORKS[fw]['description']}\n  - Focus: {FRAMEWORKS[fw]['focus']}\n  - Coverage: {', '.join(FRAMEWORKS[fw]['coverage'][:3])}..."
        for fw in frameworks
    ])
    
    # Compliance framework references
    compliance_refs = "\n".join([
        f"- **{req}** - Regulatory compliance framework"
        for req in project_info.get('compliance', [])
    ])
    
    prompt = f"""You are an expert cybersecurity consultant specializing in threat modeling and risk assessment. 
Perform a comprehensive threat assessment for the following project using the {frameworks_str} framework(s).

**PROJECT INFORMATION:**
- Project Name: {project_info['name']}
- Application Type: {project_info['app_type']}
- Deployment Model: {project_info['deployment']}
- Business Criticality: {project_info['criticality']}
- Compliance Requirements: {', '.join(project_info.get('compliance', []))}
- Environment: {project_info['environment']}
- Assessment Date: {assessment_date}

**UPLOADED DOCUMENTATION:**
{documents_content}

**THREAT MODELING FRAMEWORK(S):** {frameworks_str}
{framework_descriptions}

**SPECIFIC RISK FOCUS AREAS TO ASSESS:**
{risk_areas_details}

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

# THREAT MODELING ANALYSIS - {frameworks_str}

**Summary:** [2-3 sentence overview of the threat modeling analysis, the framework's approach, and key findings discovered during the analysis]

Comprehensive threat analysis organized by {frameworks_str} categories with risk scoring and mitigation paths, **with evidence citations and concrete examples from uploaded documentation**.

For each relevant category in {frameworks_str}, provide detailed analysis:

## [Category Name]

**Summary:** [1-2 sentences describing the threats found in this category and their overall risk level]

| Threat ID | Threat Description | Document Evidence | Example from Documentation | Likelihood | Impact | Risk Score | Recommended Mitigation |
|-----------|-------------------|-------------------|---------------------------|-----------|--------|-----------|----------------------|
| T001 | [threat description] | [Doc: Name, Section/Quote] | [Specific example from doc] | [1-5] | [1-5] | [score] | [mitigation] |

---

# SPECIALIZED RISK ASSESSMENTS

**Summary:** [2-3 sentences describing the selected risk focus areas, why they're important for this project, and the overall risk landscape across these areas]

{risk_areas_sections}

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
| **2 - Minor** | 2 | 4 | 6 | 8 | 10 |
| **1 - Negligible** | 1 | 2 | 3 | 4 | 5 |

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
| R001 | [action] | CRITICAL | [% reduction] | [step 1, 2, 3...] | [effort estimate] | [owner] | [date] |

## P1 - HIGH (Remediate in 30-90 days)

**High-priority improvements that significantly reduce risk exposure.**

| Rec ID | Recommendation | Current Risk | Risk Reduction | Implementation Steps | Required Effort | Owner | Target Completion |
|--------|---------------|--------------|----------------|---------------------|-----------------|-------|------------------|
| R010 | [action] | HIGH | [% reduction] | [step 1, 2, 3...] | [effort estimate] | [owner] | [date] |

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
{compliance_rows}

---

# REFERENCES

**Threat Modeling Frameworks:**
{framework_refs}

**Security Standards & Guidelines:**
- [NIST SP 800-53 Rev 5](https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final) - Security and Privacy Controls for Information Systems and Organizations
- [OWASP Top 10 2021](https://owasp.org/www-project-top-ten/) - Top 10 Web Application Security Risks
- [MITRE ATT&CK Framework](https://attack.mitre.org/) - Adversary Tactics, Techniques, and Common Knowledge
- [CIS Critical Security Controls v8](https://www.cisecurity.org/controls/v8) - Critical Security Controls for Effective Cyber Defense
- [ISO/IEC 27001:2013](https://www.iso.org/standard/54534.html) - Information Security Management Systems Requirements

**Compliance Frameworks:**
{compliance_refs}

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
    
    return prompt
