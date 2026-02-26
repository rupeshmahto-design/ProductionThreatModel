export interface ProjectDocument {
  id: string;
  name: string;
  type: string;
  size: string;
  content: string;
  category: string;
}

export interface ThreatAssessment {
  overallRiskScore: number;
  summary: string;
  threats: ThreatItem[];
  attackVectors: AttackVector[];
  mitigations: Mitigation[];
  complianceGaps: ComplianceGap[];
  recommendations: string[];
  riskMatrix: RiskMatrix;
}

export interface ThreatItem {
  id: string;
  category: string;
  threat: string;
  severity: 'Critical' | 'High' | 'Medium' | 'Low';
  likelihood: string;
  impact: string;
  affectedAssets: string[];
  description: string;
}

export interface AttackVector {
  vector: string;
  technique: string;
  mitreId?: string;
  description: string;
  exploitability: string;
}

export interface Mitigation {
  threat: string;
  control: string;
  priority: 'Critical' | 'High' | 'Medium' | 'Low';
  status: 'Implemented' | 'Planned' | 'Required';
  effort: string;
  description: string;
}

export interface ComplianceGap {
  framework: string;
  requirement: string;
  currentState: string;
  gap: string;
  remediation: string;
}

export interface RiskMatrix {
  critical: number;
  high: number;
  medium: number;
  low: number;
}

export interface User {
  id: number;
  email: string;
  full_name: string;
  role: string;
  is_active: boolean;
  created_at: string;
}

export interface SavedReport {
  id: number;
  project_name: string;
  project_number: string;
  project_stage: string;
  overall_score: number;
  created_at: string;
  user_id: number;
}
