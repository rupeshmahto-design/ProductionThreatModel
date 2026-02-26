import React, { useState, useEffect } from 'react';
import { useAuth } from './context/AuthContext';
import { Login } from './components/Login';
import { Register } from './components/Register';
import { AdminDashboard } from './components/AdminDashboard';
import { ComplianceDocumentation } from './components/ComplianceDocumentation';
import FileUpload from './components/FileUpload';
import ReportHistory from './components/ReportHistory';
import Sidebar from './components/Sidebar';
import { ProjectDocument } from './types';
import { PROJECT_STAGES, FRAMEWORKS, FRAMEWORK_DESCRIPTIONS, BUSINESS_CRITICALITY, APPLICATION_TYPES, 
         DEPLOYMENT_MODELS, ENVIRONMENTS, RISK_FOCUS_AREAS, RISK_AREA_DESCRIPTIONS, COMPLIANCE_REQUIREMENTS, API_BASE_URL } from './constants';

type ViewType = 'upload' | 'dashboard' | 'report' | 'history' | 'admin' | 'compliance';

// Simple markdown to HTML converter
const markdownToHtml = (markdown: string): string => {
  // Normalize line endings
  let html = markdown.replace(/\r\n/g, '\n').replace(/\r/g, '\n');
  
  // Process line by line for better control
  const lines = html.split('\n');
  const processedLines: string[] = [];
  let inTable = false;
  let tableBuffer: string[] = [];
  let inCodeBlock = false;
  let codeBuffer: string[] = [];
  
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const trimmed = line.trim();
    
    // Handle code blocks
    if (trimmed.startsWith('```')) {
      if (inCodeBlock) {
        // End code block
        processedLines.push(`<pre class="bg-gray-100 p-4 rounded overflow-x-auto my-4 text-sm"><code>${codeBuffer.join('\n')}</code></pre>`);
        codeBuffer = [];
        inCodeBlock = false;
      } else {
        // Start code block
        inCodeBlock = true;
      }
      continue;
    }
    
    if (inCodeBlock) {
      codeBuffer.push(line);
      continue;
    }
    
    // Handle tables
    if (trimmed.startsWith('|') && trimmed.endsWith('|')) {
      if (!inTable) {
        inTable = true;
        tableBuffer = [];
      }
      tableBuffer.push(line);
      continue;
    } else if (inTable) {
      // End of table - process it
      if (tableBuffer.length >= 2) {
        const headers = tableBuffer[0].split('|').filter(c => c.trim()).map(h => h.trim());
        const rows = tableBuffer.slice(2).map(row => 
          row.split('|').filter(c => c.trim()).map(c => c.trim())
        );
        processedLines.push(`<table class="min-w-full border-collapse my-6"><thead><tr>${
          headers.map(h => `<th class="border border-gray-300 px-4 py-2 bg-blue-600 text-white text-left">${h}</th>`).join('')
        }</tr></thead><tbody>${
          rows.map(row => `<tr>${row.map(c => `<td class="border border-gray-300 px-4 py-2">${c}</td>`).join('')}</tr>`).join('')
        }</tbody></table>`);
      }
      inTable = false;
      tableBuffer = [];
    }
    
    // Handle headings with inline styles
    if (trimmed.startsWith('### ')) {
      const text = trimmed.substring(4);
      processedLines.push(`<h3 style="color: #475569; font-size: 1.25rem; font-weight: 600; margin-top: 1.5rem; margin-bottom: 0.75rem;">${text}</h3>`);
      continue;
    }
    
    if (trimmed.startsWith('## ')) {
      const text = trimmed.substring(3);
      processedLines.push(`<h2 style="color: #334155; font-size: 1.5rem; font-weight: 700; margin-top: 2rem; margin-bottom: 1rem; border-left: 5px solid #3b82f6; padding-left: 1rem; background: linear-gradient(90deg, #eff6ff 0%, transparent 100%); padding-top: 0.5rem; padding-bottom: 0.5rem;">${text}</h2>`);
      continue;
    }
    
    if (trimmed.startsWith('# ')) {
      const text = trimmed.substring(2);
      processedLines.push(`<h1 style="color: #1e293b; font-size: 2rem; font-weight: 800; margin-top: 2.5rem; margin-bottom: 1.5rem; border-bottom: 3px solid #3b82f6; padding-bottom: 0.75rem;">${text}</h1>`);
      continue;
    }
    
    // Handle horizontal rules
    if (trimmed === '---' || trimmed === '***') {
      processedLines.push('<hr class="my-6 border-t-2 border-gray-300" />');
      continue;
    }
    
    // Handle blockquotes
    if (trimmed.startsWith('> ')) {
      const text = trimmed.substring(2);
      processedLines.push(`<blockquote class="border-l-4 border-blue-500 pl-4 my-4 italic text-gray-700">${text}</blockquote>`);
      continue;
    }
    
    // Handle unordered lists
    if (trimmed.startsWith('- ')) {
      const text = trimmed.substring(2);
      // Process inline formatting
      const formatted = text
        .replace(/\*\*(.+?)\*\*/g, '<strong class="font-semibold">$1</strong>')
        .replace(/\*(.+?)\*/g, '<em>$1</em>');
      processedLines.push(`<li class="ml-6 my-1">${formatted}</li>`);
      continue;
    }
    
    // Handle ordered lists
    if (/^\d+\.\s/.test(trimmed)) {
      const text = trimmed.replace(/^\d+\.\s/, '');
      const formatted = text
        .replace(/\*\*(.+?)\*\*/g, '<strong class="font-semibold">$1</strong>')
        .replace(/\*(.+?)\*/g, '<em>$1</em>');
      processedLines.push(`<li class="ml-6 my-1">${formatted}</li>`);
      continue;
    }
    
    // Handle regular lines with inline formatting
    if (trimmed) {
      const formatted = line
        .replace(/\*\*(.+?)\*\*/g, '<strong class="font-semibold">$1</strong>')
        .replace(/\*(.+?)\*/g, '<em>$1</em>');
      processedLines.push(formatted);
    } else {
      // Empty line - add paragraph break
      processedLines.push('<br/>');
    }
  }
  
  // Wrap consecutive <li> tags in <ul> or <ol>
  let finalHtml = processedLines.join('\n');
  finalHtml = finalHtml.replace(/(<li class="ml-6 my-1">.+?<\/li>\n?)+/g, (match) => {
    return `<ul class="list-disc pl-6 my-3">${match}</ul>`;
  });
  
  return finalHtml;
};

function App() {
  const { user, token, logout, isAdmin, loading } = useAuth();
  const [view, setView] = useState<ViewType>('upload');
  const [showAuthModal, setShowAuthModal] = useState<'login' | 'register' | null>(null);
  const [sidebarOpen, setSidebarOpen] = useState(false);
  
  // Project state
  const [projectName, setProjectName] = useState('');
  const [projectNumber, setProjectNumber] = useState('');
  const [projectStage, setProjectStage] = useState(PROJECT_STAGES[0]);
  const [framework, setFramework] = useState(FRAMEWORKS[0]);
  const [frameworks, setFrameworks] = useState<string[]>([FRAMEWORKS[0]]); // Multi-select frameworks
  const [businessCriticality, setBusinessCriticality] = useState(BUSINESS_CRITICALITY[0]);
  const [applicationType, setApplicationType] = useState(APPLICATION_TYPES[0]);
  const [deploymentModel, setDeploymentModel] = useState(DEPLOYMENT_MODELS[0]);
  const [environment, setEnvironment] = useState(ENVIRONMENTS[0]);
  const [complianceRequirements, setComplianceRequirements] = useState<string[]>([]);
  const [riskFocusAreas, setRiskFocusAreas] = useState<string[]>([]);
  const [documents, setDocuments] = useState<ProjectDocument[]>([]);
  const [report, setReport] = useState<string | null>(null);
  const [currentAssessmentId, setCurrentAssessmentId] = useState<number | null>(null);
  const [reportProjects, setReportProjects] = useState<any[]>([]);
  
  // UI state
  const [isGenerating, setIsGenerating] = useState(false);
  const [error, setError] = useState('');

  // Check for authentication on mount
  useEffect(() => {
    if (!loading && !user) {
      setShowAuthModal('login');
    }
  }, [loading, user]);

  // Load saved reports when user logs in
  useEffect(() => {
    if (user && token) {
      fetchSavedReports();
    }
  }, [user, token]);

  const fetchSavedReports = async () => {
    try {
      const response = await fetch(`${API_BASE_URL}/reports`, {
        headers: {
          'Authorization': `Bearer ${token}`
        }
      });
      if (response.ok) {
        const data = await response.json();
        setReportProjects(data.projects || []);
      }
    } catch (err) {
      console.error('Failed to fetch reports:', err);
    }
  };

  const resetForm = () => {
    setProjectName('');
    setProjectNumber('');
    setProjectStage(PROJECT_STAGES[0]);
    setFramework(FRAMEWORKS[0]);
    setFrameworks([FRAMEWORKS[0]]);
    setBusinessCriticality(BUSINESS_CRITICALITY[0]);
    setApplicationType(APPLICATION_TYPES[0]);
    setDeploymentModel(DEPLOYMENT_MODELS[0]);
    setEnvironment(ENVIRONMENTS[0]);
    setComplianceRequirements([]);
    setRiskFocusAreas([]);
    setDocuments([]);
    setReport(null);
    setCurrentAssessmentId(null);
    setError('');
  };

  const handleFilesAdded = (newDocs: ProjectDocument[]) => {
    setDocuments([...documents, ...newDocs]);
    setError('');
  };

  const handleGenerateReport = async () => {
    if (!projectName || documents.length === 0) {
      setError('Please provide project name and upload at least one document');
      return;
    }

    const apiKey = localStorage.getItem('anthropic_api_key') || localStorage.getItem('api_key');
    console.log('API Key check:', apiKey ? 'Found' : 'Not found', 'Length:', apiKey?.length);
    
    if (!apiKey || apiKey.trim() === '') {
      setError('SecureAI API key is missing. Please click the Settings gear icon (⚙️) in the top right and enter your API key.');
      setSidebarOpen(true);
      return;
    }

    setIsGenerating(true);
    setError('');

    try {
      const response = await fetch(`${API_BASE_URL}/api/v1/threat-modeling`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({
          project_name: projectName,
          project_number: projectNumber,
          project_stage: projectStage,
          framework: framework,
          frameworks: frameworks, // Send multi-framework array
          business_criticality: businessCriticality,
          application_type: applicationType,
          deployment_model: deploymentModel,
          environment: environment,
          compliance_requirements: complianceRequirements,
          risk_focus_areas: riskFocusAreas,
          documents: documents,
          system_description: documents.length > 0 
            ? documents.map(doc => `Document: ${doc.name}\nCategory: ${doc.category}\nSize: ${doc.size}`).join('\n\n')
            : 'No documentation provided yet. This is a preliminary threat assessment.',
          anthropic_api_key: apiKey
        })
      });

      if (!response.ok) {
        let errorMessage = 'Failed to generate threat assessment';
        try {
          const errorData = await response.json();
          errorMessage = errorData.detail || errorMessage;
        } catch (parseError) {
          // If response is not JSON, try to get text (HTML error page)
          try {
            const errorText = await response.text();
            // Check if it's an HTML error page
            if (errorText.includes('<html>') || errorText.includes('<!DOCTYPE')) {
              errorMessage = `Server error (${response.status}). Please check the server logs for details.`;
              console.error('Server returned HTML error page:', errorText.substring(0, 500));
            } else {
              errorMessage = errorText || `Server error (${response.status})`;
            }
          } catch {
            errorMessage = `Server error (${response.status})`;
          }
        }
        
        // Show specific guidance for API key errors
        if (response.status === 401 || errorMessage.includes('API key') || errorMessage.includes('authentication')) {
          throw new Error(`❌ ${errorMessage}\n\n📝 To fix this:\n1. Go to https://console.anthropic.com/settings/keys\n2. Create a new API key\n3. Copy it and paste into Settings (sidebar) → SecureAI API Key`);
        }
        
        throw new Error(errorMessage);
      }

      const reportData = await response.json();
      setReport(reportData.report); // This is the markdown string
      setCurrentAssessmentId(reportData.id || null);
      setView('report'); // Show the professional report view instead of dashboard
      
      // Show success message
      setError('✅ Assessment completed successfully!');
      setTimeout(() => setError(''), 3000);
      
      // Refresh saved reports
      await fetchSavedReports();
    } catch (err: any) {
      setError(err.message || 'Failed to generate threat assessment. Please check your API key and try again.');
      console.error('Threat assessment generation error:', err);
    } finally {
      setIsGenerating(false);
    }
  };

  const handleDownloadPdf = async (assessmentId: number) => {
    if (!token) return;
    
    try {
      const response = await fetch(`${API_BASE_URL}/reports/${assessmentId}/pdf`, {
        headers: {
          'Authorization': `Bearer ${token}`
        }
      });
      
      if (response.ok) {
        const blob = await response.blob();
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `threat_assessment_${assessmentId}.pdf`;
        document.body.appendChild(a);
        a.click();
        window.URL.revokeObjectURL(url);
        document.body.removeChild(a);
      } else {
        setError('Failed to download PDF');
      }
    } catch (err) {
      console.error('PDF download error:', err);
      setError('Failed to download PDF');
    }
  };

  const handleViewReport = async (assessmentId: number) => {
    if (!token) return;
    
    try {
      const response = await fetch(`${API_BASE_URL}/reports/${assessmentId}`, {
        headers: {
          'Authorization': `Bearer ${token}`
        }
      });
      
      if (response.ok) {
        const data = await response.json();
        setReport(data.report);
        setCurrentAssessmentId(assessmentId);
        setView('report');
      } else {
        setError('Failed to load report');
      }
    } catch (err) {
      console.error('Report load error:', err);
      setError('Failed to load report');
    }
  };

  const handleResetForm = () => {
    setProjectName('');
    setProjectNumber('');
    setProjectStage(PROJECT_STAGES[0]);
    setFramework(FRAMEWORKS[0]);
    setFrameworks([FRAMEWORKS[0]]);
    setBusinessCriticality(BUSINESS_CRITICALITY[0]);
    setApplicationType(APPLICATION_TYPES[0]);
    setDeploymentModel(DEPLOYMENT_MODELS[0]);
    setEnvironment(ENVIRONMENTS[0]);
    setComplianceRequirements([]);
    setRiskFocusAreas([]);
    setDocuments([]);
    setReport(null);
    setCurrentAssessmentId(null);
    setView('upload');
    setError('');
  };

  const handleLoadReport = async (reportId: number) => {
    try {
      const response = await fetch(`${API_BASE_URL}/reports/${reportId}`, {
        headers: {
          'Authorization': `Bearer ${token}`
        }
      });

      if (!response.ok) {
        throw new Error('Failed to load report');
      }

      const data = await response.json();
      setReport(data.report_data);
      setProjectName(data.project_name);
      setProjectNumber(data.project_number);
      setProjectStage(data.project_stage);
      setView('dashboard');
    } catch (err: any) {
      setError(err.message || 'Failed to load report');
    }
  };

  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-slate-50">
        <div className="text-center">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600 mx-auto mb-4"></div>
          <p className="text-slate-600">Loading...</p>
        </div>
      </div>
    );
  }

  if (!user) {
    return (
      <>
        {showAuthModal === 'login' && (
          <Login onSwitchToRegister={() => setShowAuthModal('register')} />
        )}
        {showAuthModal === 'register' && (
          <Register onSwitchToLogin={() => setShowAuthModal('login')} />
        )}
      </>
    );
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-50 via-blue-50 to-indigo-50">
      {/* Header */}
      <header className="bg-white border-b border-slate-200 sticky top-0 z-30 shadow-sm">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between items-center h-16">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 bg-gradient-to-br from-blue-600 to-indigo-600 rounded-lg flex items-center justify-center">
                <i className="fas fa-shield-halved text-white text-xl"></i>
              </div>
              <div>
                <h1 className="text-xl font-bold text-slate-900">Threat Modeling AI</h1>
                <p className="text-xs text-slate-500">AI-Powered Threat Analysis Platform</p>
              </div>
            </div>

            <nav className="hidden md:flex items-center gap-2">
              <button
                onClick={() => {
                  resetForm();
                  setView('upload');
                }}
                className={`px-4 py-2 rounded-lg font-medium transition-colors ${
                  view === 'upload'
                    ? 'bg-blue-100 text-blue-700'
                    : 'text-slate-600 hover:bg-slate-100'
                }`}
              >
                <i className="fas fa-upload mr-2"></i>New Assessment
              </button>
              {report && (
                <>
                  <button
                    onClick={() => setView('dashboard')}
                    className={`px-4 py-2 rounded-lg font-medium transition-colors ${
                      view === 'dashboard'
                        ? 'bg-blue-100 text-blue-700'
                        : 'text-slate-600 hover:bg-slate-100'
                    }`}
                  >
                    <i className="fas fa-chart-line mr-2"></i>Dashboard
                  </button>
                  <button
                    onClick={() => setView('report')}
                    className={`px-4 py-2 rounded-lg font-medium transition-colors ${
                      view === 'report'
                        ? 'bg-blue-100 text-blue-700'
                        : 'text-slate-600 hover:bg-slate-100'
                    }`}
                  >
                    <i className="fas fa-file-alt mr-2"></i>Full Report
                  </button>
                </>
              )}
              <button
                onClick={() => setView('history')}
                className={`px-4 py-2 rounded-lg font-medium transition-colors ${
                  view === 'history'
                    ? 'bg-blue-100 text-blue-700'
                    : 'text-slate-600 hover:bg-slate-100'
                }`}
              >
                <i className="fas fa-folder-open mr-2"></i>Past Assessments
              </button>
              {isAdmin && (
                <button
                  onClick={() => setView('admin')}
                  className={`px-4 py-2 rounded-lg font-medium transition-colors ${
                    view === 'admin'
                      ? 'bg-blue-100 text-blue-700'
                      : 'text-slate-600 hover:bg-slate-100'
                  }`}
                >
                  <i className="fas fa-user-shield mr-2"></i>Admin
                </button>
              )}
            </nav>

            <div className="flex items-center gap-2">
              <button
                onClick={() => setSidebarOpen(true)}
                className="p-2 text-slate-600 hover:bg-slate-100 rounded-lg transition-colors"
                title="Settings"
              >
                <i className="fas fa-cog text-xl"></i>
              </button>
              <div className="flex items-center gap-3 px-4 py-2 bg-slate-100 rounded-lg">
                <div className="text-right">
                  <p className="text-sm font-medium text-slate-900">{user.full_name}</p>
                  <p className="text-xs text-slate-500">{user.role}</p>
                </div>
                <button
                  onClick={logout}
                  className="p-2 text-red-600 hover:bg-red-50 rounded-lg transition-colors"
                  title="Logout"
                >
                  <i className="fas fa-sign-out-alt"></i>
                </button>
              </div>
            </div>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {error && (
          <div className="mb-6 bg-red-50 border border-red-200 text-red-700 px-4 py-3 rounded-lg flex items-start gap-3">
            <i className="fas fa-exclamation-circle mt-0.5 text-sm"></i>
            <div>
              <p className="font-medium text-sm">Error</p>
              <p className="text-xs">{error}</p>
            </div>
            <button onClick={() => setError('')} className="ml-auto text-red-700 hover:text-red-900">
              <i className="fas fa-times text-sm"></i>
            </button>
          </div>
        )}

        {view === 'upload' && (
          <div className="space-y-6">
            <div className="bg-white rounded-xl shadow-sm border border-slate-200 p-6">
              <h2 className="text-lg font-bold text-slate-900 mb-4 flex items-center gap-2">
                <i className="fas fa-info-circle text-blue-600"></i>
                Project Information
              </h2>
              
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div>
                  <label className="block text-sm font-medium text-slate-700 mb-2">
                    Project Name *
                  </label>
                  <input
                    type="text"
                    value={projectName}
                    onChange={(e) => setProjectName(e.target.value)}
                    className="w-full px-4 py-2 border border-slate-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                    placeholder="e.g., Customer Portal Modernization"
                  />
                </div>

                <div>
                  <label className="block text-sm font-medium text-slate-700 mb-2">
                    Business Criticality *
                  </label>
                  <select
                    value={businessCriticality}
                    onChange={(e) => setBusinessCriticality(e.target.value)}
                    className="w-full px-4 py-2 border border-slate-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                  >
                    {BUSINESS_CRITICALITY.map(crit => (
                      <option key={crit} value={crit}>{crit}</option>
                    ))}
                  </select>
                </div>

                <div>
                  <label className="block text-sm font-medium text-slate-700 mb-2">
                    Project Number
                  </label>
                  <input
                    type="text"
                    value={projectNumber}
                    onChange={(e) => setProjectNumber(e.target.value)}
                    className="w-full px-4 py-2 border border-slate-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                    placeholder="e.g., PRJ-2024-001"
                  />
                </div>

                <div>
                  <label className="block text-sm font-medium text-slate-700 mb-2">
                    Application Type
                  </label>
                  <select
                    value={applicationType}
                    onChange={(e) => setApplicationType(e.target.value)}
                    className="w-full px-4 py-2 border border-slate-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                  >
                    {APPLICATION_TYPES.map(type => (
                      <option key={type} value={type}>{type}</option>
                    ))}
                  </select>
                </div>

                <div>
                  <label className="block text-sm font-medium text-slate-700 mb-2">
                    Environment
                  </label>
                  <select
                    value={environment}
                    onChange={(e) => setEnvironment(e.target.value)}
                    className="w-full px-4 py-2 border border-slate-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                  >
                    {ENVIRONMENTS.map(env => (
                      <option key={env} value={env}>{env}</option>
                    ))}
                  </select>
                </div>

                <div>
                  <label className="block text-sm font-medium text-slate-700 mb-2">
                    Deployment Model
                  </label>
                  <select
                    value={deploymentModel}
                    onChange={(e) => setDeploymentModel(e.target.value)}
                    className="w-full px-4 py-2 border border-slate-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                  >
                    {DEPLOYMENT_MODELS.map(model => (
                      <option key={model} value={model}>{model}</option>
                    ))}
                  </select>
                </div>

                <div className="md:col-span-2">
                  <label className="block text-sm font-medium text-slate-700 mb-3">
                    Compliance Requirements
                  </label>
                  <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                    {COMPLIANCE_REQUIREMENTS.map(req => (
                      <label
                        key={req}
                        className="flex items-center gap-2 p-2 border border-slate-200 rounded-lg cursor-pointer hover:border-blue-300 transition-all"
                      >
                        <input
                          type="checkbox"
                          checked={complianceRequirements.includes(req)}
                          onChange={(e) => {
                            if (e.target.checked) {
                              setComplianceRequirements([...complianceRequirements, req]);
                            } else {
                              setComplianceRequirements(complianceRequirements.filter(r => r !== req));
                            }
                          }}
                          className="w-4 h-4 text-blue-600"
                        />
                        <span className="text-sm font-medium text-slate-900">{req}</span>
                      </label>
                    ))}
                  </div>
                </div>

                <div>
                  <label className="block text-sm font-medium text-slate-700 mb-2">
                    Project Stage
                  </label>
                  <select
                    value={projectStage}
                    onChange={(e) => setProjectStage(e.target.value)}
                    className="w-full px-4 py-2 border border-slate-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                  >
                    {PROJECT_STAGES.map(stage => (
                      <option key={stage} value={stage}>{stage}</option>
                    ))}
                  </select>
                </div>
              </div>
            </div>

            <div className="bg-white rounded-xl shadow-sm border border-slate-200 p-6">
              <h2 className="text-2xl font-bold text-slate-900 mb-6 flex items-center gap-2">
                <i className="fas fa-upload text-orange-600"></i>
                Upload Project Documents
              </h2>
              <FileUpload onFilesAdded={handleFilesAdded} />
              
              {documents.length > 0 && (
                <div className="mt-6">
                  <h3 className="font-semibold text-slate-900 mb-3">Uploaded Documents ({documents.length})</h3>
                  <div className="space-y-2">
                    {documents.map(doc => (
                      <div key={doc.id} className="flex items-center justify-between p-3 bg-slate-50 rounded-lg">
                        <div className="flex items-center gap-3">
                          <i className="fas fa-file-alt text-blue-600"></i>
                          <div>
                            <p className="font-medium text-slate-900">{doc.name}</p>
                            <p className="text-xs text-slate-500">{doc.category} • {doc.size}</p>
                          </div>
                        </div>
                        <button
                          onClick={() => setDocuments(documents.filter(d => d.id !== doc.id))}
                          className="text-red-600 hover:text-red-700"
                        >
                          <i className="fas fa-trash"></i>
                        </button>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>

            <div className="bg-white rounded-xl shadow-sm border border-slate-200 p-6">
              <h2 className="text-2xl font-bold text-slate-900 mb-6 flex items-center gap-2">
                <i className="fas fa-shield-alt text-red-600"></i>
                Select Threat Modeling Frameworks (Multi-Select)
              </h2>
              
              <p className="text-sm text-slate-600 mb-4">
                Select one or more frameworks for comprehensive threat analysis. Multiple frameworks provide broader coverage.
              </p>
              
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                {FRAMEWORKS.map(fw => (
                  <div
                    key={fw}
                    onClick={() => {
                      if (fw === 'Custom Client Framework') return; // Disabled
                      if (frameworks.includes(fw)) {
                        // Don't allow deselecting all frameworks
                        if (frameworks.length > 1) {
                          setFrameworks(frameworks.filter(f => f !== fw));
                          // Update single framework state for backward compatibility
                          const remaining = frameworks.filter(f => f !== fw);
                          setFramework(remaining[0]);
                        }
                      } else {
                        setFrameworks([...frameworks, fw]);
                        // Update single framework state for backward compatibility
                        setFramework(fw);
                      }
                    }}
                    className={`p-4 border-2 rounded-lg transition-all ${
                      fw === 'Custom Client Framework'
                        ? 'border-slate-200 bg-slate-50 opacity-60 cursor-not-allowed'
                        : frameworks.includes(fw)
                        ? 'border-blue-600 bg-blue-50 cursor-pointer'
                        : 'border-slate-200 hover:border-blue-300 cursor-pointer'
                    }`}
                    title={FRAMEWORK_DESCRIPTIONS[fw] || ''}
                  >
                    <div className="flex items-center gap-2 mb-2">
                      <input
                        type="checkbox"
                        checked={frameworks.includes(fw)}
                        disabled={fw === 'Custom Client Framework'}
                        onChange={() => {
                          if (fw === 'Custom Client Framework') return;
                          if (frameworks.includes(fw)) {
                            if (frameworks.length > 1) {
                              setFrameworks(frameworks.filter(f => f !== fw));
                              const remaining = frameworks.filter(f => f !== fw);
                              setFramework(remaining[0]);
                            }
                          } else {
                            setFrameworks([...frameworks, fw]);
                            setFramework(fw);
                          }
                        }}
                        className="text-blue-600 w-4 h-4"
                      />
                      <div className="flex items-center gap-2 flex-1">
                        <h3 className={`font-bold ${fw === 'Custom Client Framework' ? 'text-slate-500' : 'text-slate-900'}`}>{fw}</h3>
                        {fw === 'Custom Client Framework' && (
                          <span className="inline-flex items-center px-2 py-1 text-xs font-medium bg-amber-100 text-amber-800 rounded-full border border-amber-300">
                            <i className="fas fa-star mr-1"></i>Customize with Client
                          </span>
                        )}
                      </div>
                    </div>
                    <p className={`text-xs ${fw === 'Custom Client Framework' ? 'text-slate-400' : 'text-slate-600'}`}>
                      {fw === 'MITRE ATT&CK' && 'Comprehensive framework for understanding adversary behavior'}
                      {fw === 'STRIDE' && "Microsoft's threat modeling methodology"}
                      {fw === 'PASTA' && 'Process for Attack Simulation and Threat Analysis'}
                      {fw === 'OCTAVE' && 'Operationally Critical Threat, Asset, and Vulnerability Evaluation'}
                      {fw === 'VAST' && 'Visual, Agile, and Simple Threat modeling'}
                      {fw === 'Custom Client Framework' && 'Organization-specific threat modeling approach'}
                    </p>
                  </div>
                ))}
              </div>
              
              {frameworks.length > 1 && (
                <div className="mt-4 p-3 bg-green-50 border border-green-200 rounded-lg">
                  <p className="text-sm text-green-800 font-medium">
                    <i className="fas fa-check-circle mr-2"></i>
                    {frameworks.length} frameworks selected: {frameworks.join(' + ')}
                  </p>
                </div>
              )}
            </div>

            <div className="bg-white rounded-xl shadow-sm border border-slate-200 p-6">
              <h2 className="text-2xl font-bold text-slate-900 mb-6 flex items-center gap-2">
                <i className="fas fa-crosshairs text-purple-600"></i>
                Select Risk Focus Areas
              </h2>
              
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {RISK_FOCUS_AREAS.map(area => (
                  <label
                    key={area}
                    className="flex items-center gap-3 p-4 border-2 border-slate-200 rounded-lg cursor-pointer hover:border-blue-300 transition-all"
                    title={RISK_AREA_DESCRIPTIONS[area] || ''}
                  >
                    <input
                      type="checkbox"
                      checked={riskFocusAreas.includes(area)}
                      onChange={(e) => {
                        if (e.target.checked) {
                          setRiskFocusAreas([...riskFocusAreas, area]);
                        } else {
                          setRiskFocusAreas(riskFocusAreas.filter(a => a !== area));
                        }
                      }}
                      className="w-5 h-5 text-blue-600"
                    />
                    <div>
                      <div className="font-semibold text-slate-900">{area}</div>
                      <div className="text-xs text-slate-600">{RISK_AREA_DESCRIPTIONS[area]}</div>
                    </div>
                  </label>
                ))}
              </div>
            </div>

            <div className="flex justify-center">
              <button
                onClick={handleGenerateReport}
                disabled={isGenerating || !projectName || documents.length === 0}
                className="px-8 py-4 bg-gradient-to-r from-red-600 to-orange-600 text-white rounded-lg font-bold text-lg hover:from-red-700 hover:to-orange-700 disabled:from-gray-400 disabled:to-gray-400 disabled:cursor-not-allowed transition-all shadow-lg hover:shadow-xl flex items-center gap-3"
              >
                {isGenerating ? (
                  <>
                    <i className="fas fa-spinner fa-spin"></i>
                    Generating Threat Assessment...
                  </>
                ) : (
                  <>
                    <i className="fas fa-shield-virus"></i>
                    Generate Threat Assessment Report
                  </>
                )}
              </button>
            </div>
          </div>
        )}

        {view === 'dashboard' && report && (
          <div className="space-y-6">
            <div className="flex justify-between items-center">
              <h2 className="text-2xl font-bold text-slate-900">📈 Assessment Dashboard</h2>
              <button
                onClick={() => setView('report')}
                className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors"
              >
                <i className="fas fa-file-alt mr-2"></i>View Full Report
              </button>
            </div>
            
            <div className="bg-white rounded-xl shadow-sm border border-slate-200 p-6">
              <p className="text-center text-gray-500 py-12">
                <i className="fas fa-chart-pie text-6xl text-gray-300 mb-4"></i>
                <br />
                Dashboard visualization coming soon. For now, please view the Full Report.
              </p>
            </div>
          </div>
        )}

        {view === 'report' && report && (
          <div className="space-y-6">
            <div className="flex justify-between items-center">
              <h2 className="text-2xl font-bold text-slate-900">📊 Assessment Report</h2>
              <div className="flex gap-2">
                <button
                  onClick={() => currentAssessmentId && handleDownloadPdf(currentAssessmentId)}
                  disabled={!currentAssessmentId}
                  className="px-4 py-2 bg-red-600 text-white rounded-lg hover:bg-red-700 transition-colors disabled:bg-gray-400 disabled:cursor-not-allowed"
                >
                  <i className="fas fa-download mr-2"></i>Download PDF
                </button>
                <button
                  onClick={() => setView('history')}
                  className="px-4 py-2 bg-slate-600 text-white rounded-lg hover:bg-slate-700 transition-colors"
                >
                  <i className="fas fa-arrow-left mr-2"></i>Back to Past Assessments
                </button>
                <button
                  onClick={handleResetForm}
                  className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors"
                >
                  <i className="fas fa-plus mr-2"></i>New Assessment
                </button>
              </div>
            </div>
            <div className="bg-white rounded-lg shadow-lg" style={{ padding: '3rem', margin: '0 auto', maxWidth: '1200px' }}>
              <div 
                className="prose prose-lg max-w-none"
                style={{ 
                  lineHeight: '1.8',
                  fontSize: '0.95rem',
                  color: '#374151'
                }}
                dangerouslySetInnerHTML={{ 
                  __html: markdownToHtml(report)
                    .replace(/CRITICAL/g, '<span style="color: #dc2626; background: #fee2e2; padding: 3px 10px; border-radius: 6px; font-weight: 700; font-size: 0.85em;">CRITICAL</span>')
                    .replace(/HIGH(?!ER)/g, '<span style="color: #ea580c; background: #ffedd5; padding: 3px 10px; border-radius: 6px; font-weight: 700; font-size: 0.85em;">HIGH</span>')
                    .replace(/MEDIUM/g, '<span style="color: #ca8a04; background: #fef3c7; padding: 3px 10px; border-radius: 6px; font-weight: 700; font-size: 0.85em;">MEDIUM</span>')
                    .replace(/\bLOW\b/g, '<span style="color: #16a34a; background: #dcfce7; padding: 3px 10px; border-radius: 6px; font-weight: 700; font-size: 0.85em;">LOW</span>')
                    .replace(/P0/g, '<span style="color: #dc2626; background: #fee2e2; padding: 2px 8px; border-radius: 4px; font-weight: 700; font-size: 0.8em;">P0</span>')
                    .replace(/P1/g, '<span style="color: #ea580c; background: #ffedd5; padding: 2px 8px; border-radius: 4px; font-weight: 700; font-size: 0.8em;">P1</span>')
                    .replace(/P2/g, '<span style="color: #ca8a04; background: #fef3c7; padding: 2px 8px; border-radius: 4px; font-weight: 700; font-size: 0.8em;">P2</span>')
                }} 
              />
            </div>
          </div>
        )}

        {view === 'history' && (
          <ReportHistory 
            projects={reportProjects}
            onViewReport={handleViewReport}
            onDownloadPdf={handleDownloadPdf}
          />
        )}

        {view === 'history-old' && (
          <div className="space-y-6">
            <div className="flex justify-between items-center">
              <h2 className="text-2xl font-bold text-slate-900">Report History</h2>
              <button
                onClick={() => setView('upload')}
                className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors"
              >
                <i className="fas fa-plus mr-2"></i>New Report
              </button>
            </div>
            <ReportHistory reports={savedReports} onLoadReport={handleLoadReport} />
          </div>
        )}

        {view === 'admin' && isAdmin && (
          <div className="space-y-6">
            <h2 className="text-2xl font-bold text-slate-900">Admin Dashboard</h2>
            <AdminDashboard />
          </div>
        )}

        {view === 'compliance' && (
          <ComplianceDocumentation />
        )}
      </main>

      {/* Footer */}
      <footer className="bg-gradient-to-br from-slate-50 to-slate-100 border-t border-slate-200 mt-auto">
        <div className="max-w-7xl mx-auto px-6 py-12">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-8">
            {/* Left Section - Branding */}
            <div className="space-y-4">
              <div className="flex items-center gap-2">
                <div className="w-10 h-10 bg-gradient-to-br from-blue-600 to-indigo-600 rounded-lg flex items-center justify-center">
                  <i className="fas fa-shield-alt text-white text-xl"></i>
                </div>
                <h3 className="text-xl font-bold bg-gradient-to-r from-blue-600 to-indigo-600 bg-clip-text text-transparent">
                  THREAT MODELING AI
                </h3>
              </div>
              <p className="text-sm text-slate-600 leading-relaxed">
                An AI-powered threat assessment platform designed for enterprise security and compliance. 
                Built for security teams, PMOs, and executive oversight.
              </p>
            </div>

            {/* Middle Section - Frameworks */}
            <div className="space-y-3">
              <h4 className="text-sm font-bold text-slate-900 uppercase tracking-wider">Security Frameworks</h4>
              <ul className="space-y-2">
                <li className="flex items-center gap-2 text-sm text-slate-600">
                  <i className="fas fa-check text-green-600 text-xs"></i>
                  <span>MITRE ATT&CK</span>
                </li>
                <li className="flex items-center gap-2 text-sm text-slate-600">
                  <i className="fas fa-check text-green-600 text-xs"></i>
                  <span>STRIDE Methodology</span>
                </li>
                <li className="flex items-center gap-2 text-sm text-slate-600">
                  <i className="fas fa-check text-green-600 text-xs"></i>
                  <span>PASTA Framework</span>
                </li>
                <li className="flex items-center gap-2 text-sm text-slate-600">
                  <i className="fas fa-check text-green-600 text-xs"></i>
                  <span>ISO 31000 Risk</span>
                </li>
              </ul>
            </div>

            {/* Right Section - Legal & Security */}
            <div className="space-y-3">
              <h4 className="text-sm font-bold text-slate-900 uppercase tracking-wider">Enterprise & Security</h4>
              <ul className="space-y-2">
                <li className="flex items-center gap-2 text-sm text-slate-600">
                  <i className="fas fa-file-alt text-blue-600 text-xs"></i>
                  <span>Audit Logs</span>
                </li>
                <li className="flex items-center gap-2 text-sm text-slate-600">
                  <i className="fas fa-lock text-blue-600 text-xs"></i>
                  <span>Data Privacy</span>
                </li>
                <li className="flex items-center gap-2 text-sm text-slate-600">
                  <i className="fas fa-key text-blue-600 text-xs"></i>
                  <span>API Credentials</span>
                </li>
                <li className="flex items-center gap-2 text-sm text-slate-600 cursor-pointer hover:text-blue-700" onClick={() => setView('compliance')}>
                  <i className="fas fa-certificate text-blue-600 text-xs"></i>
                  <span className="hover:underline">ISO 42001 Compliance</span>
                </li>
              </ul>
            </div>
          </div>

          {/* Bottom Bar */}
          <div className="mt-8 pt-6 border-t border-slate-200 flex flex-col md:flex-row justify-between items-center gap-4">
            <p className="text-xs text-slate-500">
              © {new Date().getFullYear()} Threat Modeling AI Systems. All rights reserved.
            </p>
            <div className="flex items-center gap-4 text-xs text-slate-500">
              <span className="flex items-center gap-1">
                <i className="fas fa-code-branch text-blue-600"></i>
                <span className="font-semibold">v1.1.1</span>
              </span>
              <span>•</span>
              <span className="flex items-center gap-1">
                <i className="fas fa-shield-alt text-green-600"></i>
                <span className="font-semibold">Encrypted Session</span>
              </span>
            </div>
          </div>
        </div>
      </footer>

      {/* Sidebar */}
      <Sidebar isOpen={sidebarOpen} onClose={() => setSidebarOpen(false)} />
    </div>
  );
}

export default App;
