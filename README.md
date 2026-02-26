# 🔒 AI-Powered Threat Modeling Tool

Enterprise-grade threat assessment platform powered by SecureAI (Anthropic). Generate comprehensive threat models in minutes, not days.

[![Open in Streamlit](https://static.streamlit.io/badges/streamlit_badge_black_white.svg)](https://your-streamlit-app-url.example.com)
<!-- Replace the link above with your deployed Streamlit app URL -->

![Version](https://img.shields.io/badge/version-1.1.1-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Python](https://img.shields.io/badge/python-3.11+-blue)

## ✨ Features

- **🎯 Multiple Threat Modeling Frameworks**

  - MITRE ATT&CK
  - STRIDE
  - PASTA
  - OCTAVE
  - VAST

- **🤖 AI-Powered Analysis**

  - Automated threat identification
  - Risk assessment and prioritization
  - Attack scenario generation
  - Comprehensive security recommendations

- **📊 Specialized Risk Assessments**

  - **Agentic AI Risk:** Autonomous AI systems security
  - **Model Risk:** ML/AI model deployment risks
  - **Data Security Risk:** Data protection and privacy
  - **Infrastructure Risk:** Cloud and network security
  - **Compliance Risk:** Regulatory requirements

- **📄 Professional Reporting**

  - Executive summaries
  - Detailed technical analysis
  - Risk matrices and heat maps
  - Prioritized recommendations (P0-P3)
  - Compliance mapping
  - PDF export capability
  - HTML preview in-app

- **🎨 Beautiful, Client-Facing UI**

  - Gradient theme with professional styling
  - Intuitive document upload
  - Real-time processing status
  - Interactive framework selection
  - Responsive design
  - Logo and branding customization

- **🏢 Branding & Customization**

  - Upload company logo
  - Custom header/footer text
  - Branded PDF reports
  - Client-ready output

- **🔍 PDF Generation & Diagnostics**

  - WeasyPrint-based PDF export (optional)
  - In-built diagnostics for PDF generation issues
  - One-click WeasyPrint health check
  - Markdown fallback when PDF unavailable

## 🚀 Quick Start

### Prerequisites

- Python 3.11 or higher
- SecureAI API key (Anthropic) ([Get one here](https://console.anthropic.com/))

### Installation

1. **Clone the repository**

   ```bash
   git clone <your-repo-url>
   cd threat-modeling-tool
   ```

2. **Install dependencies**

   ```bash
   pip install -r requirements.txt
   ```

3. **Run the application**
   ```bash
   streamlit run app.py
   ```

### Quick Local Run (PowerShell)

```powershell
# Create and activate venv (Windows)
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1

# Install dependencies
pip install -r requirements.txt

# Optional: set API key for this session
$env:SECUREAI_API_KEY = "your-actual-api-key"

# Run the app (defaults to port 8501)
streamlit run app.py
```

## ✅ Smoke Test (Local + CI)

We include a small smoke test to verify the local `generate_threat_assessment` function works without making network calls.

- Run locally (inside your Python 3.11 venv):

```bash
# activate your venv (example for Windows cmd)
venv311\Scripts\activate

# run the smoke test
python smoke_test.py
```

- A GitHub Actions workflow named **Smoke tests** runs this test on push and pull requests to `main`.

If the smoke test fails locally, paste the output here and we can diagnose further.

````

4. **Open your browser**
- Navigate to `http://localhost:8501`
- Enter your SecureAI API key in the sidebar
- Start creating threat assessments!

## 🌐 Web Deployment
See "Deploy to Streamlit Cloud" below for the fastest path. The app uses `packages.txt` to install WeasyPrint system dependencies automatically on Streamlit Cloud.

## 🎨 Recent Enhancements (v1.1.0)

### 1. **WeasyPrint Diagnostics**
- One-click health check button in the sidebar
- Detailed error messages if PDF generation fails
- Direct links to troubleshooting documentation
- Automatic fallback to Markdown when PDF unavailable

### 2. **In-App PDF/HTML Preview**
- Rendered HTML preview of your report before downloading
- See exactly how your PDF will look in the browser
- Support for both PDF and Markdown preview modes

### 3. **Branding & Customization**
- Upload company logo (appears in PDF header)
- Set company/project name
- Custom footer text on every PDF page
- Professional branding options for client delivery

### 4. **Enhanced PDF Styling**
- Professional header/footer with page numbers
- Improved table of contents formatting
- Better typography and spacing
- Colored risk levels and highlighting
- Logo embedding support

### 5. **Improved UI/UX**
- Gradient theme with professional colors
- Enhanced button styling with smooth transitions
- Better section organization
- Clearer visual hierarchy
- Client-facing wording and layout

### 6. **Comprehensive Testing**
- Unit tests for all new features (10 tests, all passing)
- PDF generation tests with mocked dependencies
- Branding and preview tests
- WeasyPrint health check tests
- Smoke tests for core threat assessment

### 7. **E2E Verification Script**
- `e2e_verify.py` script for testing the full pipeline
- Validates PDF generation (when WeasyPrint available)
- Tests report structure and required sections
- Provides detailed diagnostics

## 🔧 How to Use New Features

### Branding Your Reports

1. **Upload Logo:**
   - Click "Upload Company Logo" in the sidebar
   - Select a PNG, JPG, or GIF file
   - Logo appears in PDF header

2. **Set Company Name:**
   - Enter your company/project name in the sidebar
   - Appears in PDF title and header

3. **Add Footer:**
   - Enter footer text (e.g., "Confidential")
   - Appears at the bottom of every PDF page

### Checking PDF Support

1. **Click "🔍 Check WeasyPrint"** in the sidebar
2. See instant feedback:
   - ✅ If available, shows version
   - ❌ If missing, shows what's needed
   - Direct links to install troubleshooting

### Previewing Reports

1. Generate a threat assessment
2. **See HTML preview** of your report in-app
3. **Download as PDF** (if available) or Markdown
4. Reports include table of contents, executive summary, and references

### Running E2E Tests

Verify the complete PDF pipeline locally:

```bash
python e2e_verify.py
```

This tests:
- Dependency availability
- PDF generation (if WeasyPrint installed)
- Report structure validation
- Output file creation

---

## 📖 Documentation

- [INSTALLATION_GUIDE.md](INSTALLATION_GUIDE.md) - Detailed setup instructions, PDF troubleshooting
- [GETTING_STARTED.md](GETTING_STARTED.md) - Step-by-step tutorial
- [QUICKSTART.md](QUICKSTART.md) - 5-minute getting started
- [DEPLOYMENT.md](DEPLOYMENT.md) - Production deployment guide

### Deploy to Streamlit Cloud (Easiest)

1. **Push code to GitHub**
```bash
git init
git add .
git commit -m "Initial commit"
git remote add origin <your-github-repo>
git push -u origin main
````

2. **Deploy on Streamlit Cloud**

   - Go to [share.streamlit.io](https://share.streamlit.io)
   - Connect your GitHub account
   - Select your repository
   - Click "Deploy"

3. **Configure secrets**

   - In Streamlit Cloud dashboard
   - Go to App settings → Secrets
   - Add your API key (required)

   ```toml
   SECUREAI_API_KEY = "your-actual-api-key"
   ```

   - No extra build steps needed: `packages.txt` installs WeasyPrint native libraries automatically for fully formatted PDFs.

### Deploy to Heroku

1. **Create Heroku app**

   ```bash
   heroku create your-app-name
   ```

2. **Add buildpack**

   ```bash
   heroku buildpacks:set heroku/python
   ```

3. **Deploy**

   ```bash
   git push heroku main
   ```

4. **Open app**
   ```bash
   heroku open
   ```

### Deploy with Docker (optional, local parity with Cloud)

1. **Build Docker image**

   ```bash
   docker build -t threat-modeling-tool .
   ```

2. **Run container**

   ```bash
   docker run -p 8501:8501 threat-modeling-tool
   ```

3. **Access application**
   - Open `http://localhost:8501`

## 📖 Usage Guide

### 1. Project Setup

Fill in your project details:

- **Project Name:** Name of the system being assessed
- **Application Type:** Web, Mobile, API, etc.
- **Deployment Model:** Cloud provider or on-premises
- **Business Criticality:** Impact level if compromised
- **Compliance Requirements:** Applicable regulations

### 2. Upload Documents

Upload your project artifacts:

- Architecture diagrams (PNG, JPG, PDF)
- Design documents (PDF, DOCX, MD, TXT)
- Network diagrams
- Data flow diagrams
- API specifications (YAML, JSON)
- Technical documentation

**Supported Formats:**

- Images: PNG, JPG, JPEG
- Documents: PDF, DOCX, TXT, MD
- Data: YAML, JSON

### 3. Select Framework

Choose your threat modeling framework:

- **MITRE ATT&CK:** Comprehensive adversary tactics
- **STRIDE:** Application security focus
- **PASTA:** Risk-centric approach
- **OCTAVE:** Enterprise risk management
- **VAST:** Agile threat modeling

### 4. Select Risk Areas

Pick specific risk focus areas:

- ✅ Agentic AI Risk (autonomous AI systems)
- ✅ Model Risk (ML/AI deployment)
- ✅ Data Security Risk
- ✅ Infrastructure Risk
- ✅ Compliance Risk

### 5. Generate Assessment

Click "Generate Threat Assessment Report" and wait for:

1. Document processing
2. AI analysis
3. Report generation

### 6. Download Report

Get your comprehensive threat assessment as:

- Markdown file (ready for conversion to PDF)
- Includes all sections and recommendations

## 📊 Report Structure

Generated reports include:

1. **Executive Summary**

   - Overall risk rating
   - Top 5 critical findings
   - Key recommendations

2. **Threat Modeling Analysis**

   - Framework-specific threat analysis
   - Attack scenarios
   - Risk ratings

3. **Specialized Risk Assessments**

   - Detailed analysis per selected risk area
   - Specific threat evaluations
   - Mitigation strategies

4. **Component-Specific Analysis**

   - Frontend/UI threats
   - Backend/Application layer
   - Database/Data layer
   - API/Integration layer
   - Infrastructure/Cloud

5. **Attack Scenarios & Kill Chains**

   - Realistic attack paths
   - Detection opportunities
   - Mitigation strategies

6. **Risk Assessment Matrix**

   - Likelihood × Impact scoring
   - Priority classification

7. **Prioritized Recommendations**

   - P0: Critical (0-30 days)
   - P1: High (30-90 days)
   - P2: Medium (90-180 days)
   - P3: Low (180+ days)

8. **Security Controls Mapping**

   - Preventive controls
   - Detective controls
   - Corrective controls

9. **Compliance Considerations**

   - Regulatory requirement mapping
   - Compliance gaps

10. **Metrics and KPIs**
    - Security metrics to track
    - Monitoring priorities

## 🔐 Security Considerations

- **API Key Security:** Never commit API keys to version control
- **Data Privacy:** Uploaded documents are processed in-memory only
- **Session Isolation:** Each user session is independent
- **HTTPS:** Use HTTPS in production deployments
- **Access Control:** Implement authentication for enterprise use

## 🛠️ Configuration

### Environment Variables

Create a `.env` file (optional):

```env
SECUREAI_API_KEY=your_api_key_here
STREAMLIT_SERVER_PORT=8501
STREAMLIT_SERVER_ADDRESS=0.0.0.0
```

### Streamlit Configuration

Create `.streamlit/config.toml`:

```toml
[theme]
primaryColor = "#1976D2"
backgroundColor = "#FFFFFF"
secondaryBackgroundColor = "#F0F2F6"
textColor = "#262730"
font = "sans serif"

[server]
port = 8501
enableCORS = false
enableXsrfProtection = true
```

## 📈 Future Enhancements

### Planned Features

- [x] **PDF Generation:** WeasyPrint-based export with a styled fallback when native deps are missing
- [ ] **Context Storage:** Enterprise-wide knowledge base
- [ ] **User Authentication:** SSO and RBAC
- [ ] **Assessment History:** Track and compare assessments
- [ ] **Collaborative Reviews:** Team commenting and approval
- [ ] **API Integration:** REST API for programmatic access
- [ ] **Template Library:** Pre-built assessment templates
- [ ] **Automated Scheduling:** Recurring assessments
- [ ] **Integration Hub:** JIRA, ServiceNow, Slack, Teams
- [ ] **Advanced Analytics:** Trend analysis and reporting
- [ ] **Custom Frameworks:** Build your own threat models
- [ ] **Multi-language Support:** I18n capabilities

### Enterprise Features (Roadmap)

- **Database Backend:** PostgreSQL for persistence
- **Multi-tenancy:** Organization isolation
- **Audit Logging:** Complete activity tracking
- **Advanced RBAC:** Granular permissions
- **API Gateway:** Rate limiting and authentication
- **Assessment Workflows:** Approval processes
- **Integration:** SIEM, ticketing systems
- **Custom Branding:** White-label capability

## 🤝 Contributing

Contributions are welcome! Please follow these steps:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 📝 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🙏 Acknowledgments

- **Anthropic:** For the incredible Claude AI API
- **Streamlit:** For the beautiful web framework
- **MITRE:** For the ATT&CK framework
- **Security Community:** For threat modeling best practices

## 📞 Support

For issues, questions, or contributions:

- **Issues:** [GitHub Issues](https://github.com/rupeshmahto-design/threatmodelling/issues)
- **Discussions:** [GitHub Discussions](https://github.com/rupeshmahto-design/threatmodelling/discussions)
- **Email:** support@your-domain.com

## 🌟 Star History

If you find this tool useful, please consider giving it a star! ⭐

---

**Built with ❤️ for the security community**

_Last Updated: January 2026_
