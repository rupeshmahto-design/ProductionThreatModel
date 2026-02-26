export const PROJECT_STAGES = [
  'Planning',
  'Development',
  'Testing',
  'Production',
  'Maintenance'
];

export const FRAMEWORKS = [
  'MITRE ATT&CK',
  'STRIDE',
  'PASTA',
  'OCTAVE',
  'VAST',
  'Custom Client Framework'
];

export const FRAMEWORK_DESCRIPTIONS: Record<string, string> = {
  'MITRE ATT&CK': 'Adversarial tactics, techniques, and common knowledge - maps real-world threat actor behaviors',
  'STRIDE': 'Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege',
  'PASTA': 'Process for Attack Simulation and Threat Analysis - risk-centric methodology',
  'OCTAVE': 'Operationally Critical Threat, Asset, and Vulnerability Evaluation - organizational risk assessment',
  'VAST': 'Visual, Agile, and Simple Threat modeling - scalable for DevOps and agile environments',
  'Custom Client Framework': 'Organization-specific threat modeling framework tailored to your requirements'
};

export const BUSINESS_CRITICALITY = [
  'Critical',
  'High',
  'Medium',
  'Low'
];

export const APPLICATION_TYPES = [
  'Web Application',
  'Mobile Application',
  'Desktop Application',
  'API/Microservices',
  'AI/ML Project',
  'Cloud Infrastructure',
  'IoT Device',
  'Database System',
  'Other'
];

export const DEPLOYMENT_MODELS = [
  'Cloud (AWS)',
  'Cloud (Azure)',
  'Cloud (GCP)',
  'On-Premises',
  'Hybrid',
  'Multi-Cloud'
];

export const ENVIRONMENTS = [
  'Production',
  'Staging',
  'Development',
  'Testing',
  'DR/Backup'
];

export const RISK_FOCUS_AREAS = [
  'Agentic AI Risk',
  'Model Risk',
  'Data Security Risk',
  'Infrastructure Risk',
  'Compliance Risk',
  'Privacy Risk',
  'Supply Chain Risk',
  'Identity & Access Risk'
];

export const RISK_AREA_DESCRIPTIONS: Record<string, string> = {
  'Agentic AI Risk': 'Autonomous agent behavior, decision-making, prompt injection, and agent orchestration vulnerabilities',
  'Model Risk': 'AI model security including adversarial attacks, model poisoning, and inference manipulation',
  'Data Security Risk': 'Data breaches, unauthorized access, data exfiltration, and sensitive information exposure',
  'Infrastructure Risk': 'Cloud/on-prem infrastructure vulnerabilities, misconfigurations, and deployment security',
  'Compliance Risk': 'Regulatory compliance gaps (GDPR, HIPAA, SOC2) and audit requirements',
  'Privacy Risk': 'PII handling, user consent, data retention, and privacy law violations',
  'Supply Chain Risk': 'Third-party dependencies, vendor security, open-source vulnerabilities, and supply chain attacks',
  'Identity & Access Risk': 'Authentication weaknesses, authorization flaws, privilege escalation, and access control issues'
};

export const COMPLIANCE_REQUIREMENTS = [
  'SOC 2',
  'ISO 27001',
  'GDPR',
  'HIPAA',
  'PCI DSS',
  'NIST',
  'CIS Controls',
  'CCPA'
];

export const DOCUMENT_CATEGORIES = [
  'Architecture Diagram',
  'Data Flow Diagram',
  'System Design',
  'API Documentation',
  'Security Requirements',
  'Compliance Documentation',
  'Risk Assessment',
  'Incident Response Plan',
  'Other'
];

export const SEVERITY_LEVELS = {
  High: 'bg-red-100 text-red-800 border-red-300',
  Medium: 'bg-amber-100 text-amber-800 border-amber-300',
  Low: 'bg-green-100 text-green-800 border-green-300'
};

export const GOVERNANCE_STATUS = {
  Compliant: 'text-green-600',
  Partial: 'text-amber-600',
  'Non-Compliant': 'text-red-600'
};

export const USER_ROLES = [
  'user',
  'admin'
];

export const API_BASE_URL = import.meta.env.VITE_API_URL || '';
