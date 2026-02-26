# 🚀 Installation & Access Guide

## How to Get Your Threat Modeling Tool Running

---

## 📥 **DOWNLOAD THE FILES**

All files have been copied to your outputs folder. You can access them directly or download the complete package.

### Option 1: Download Individual Files (Recommended for reviewing)

Click on each file below to view/download:

**Core Application:**

- `app.py` - Main application code
- `requirements.txt` - Python dependencies

**Quick Start Scripts:**

- `setup.sh` - Automated setup (run this first!)
- `run.sh` - Start the application

**Documentation:**

- `README.md` - Complete documentation
- `QUICKSTART.md` - 5-minute getting started
- `DEPLOYMENT.md` - Full deployment guide
- `GETTING_STARTED.md` - Comprehensive overview

**Deployment Files:**

- `Dockerfile` - Container configuration
- `docker-compose.yml` - Docker Compose setup

**Configuration:**

- `.streamlit/config.toml` - UI configuration
- `.env.example` - Environment template
- `.gitignore` - Git ignore rules

### Option 2: Download Complete Archive

I can also create a ZIP file with everything if you prefer.

---

## 💻 **INSTALLATION STEPS**

### Method 1: Local Installation (Recommended for First Try)

#### Step 1: Download All Files

Download all the files from the outputs folder to a directory on your computer, for example:

```
C:\Projects\threat-modeling-tool\     (Windows)
or
~/Projects/threat-modeling-tool/      (Mac/Linux)
```

#### Step 2: Open Terminal/Command Prompt

**Windows:**

- Press `Win + R`, type `cmd`, press Enter
- Navigate to your folder: `cd C:\Projects\threat-modeling-tool`

**Mac/Linux:**

- Open Terminal
- Navigate to your folder: `cd ~/Projects/threat-modeling-tool`

#### Step 3: Install Python (if not already installed)

**Check if Python is installed:**

```bash
python --version
```

or

```bash
python3 --version
```

You need Python 3.11 or higher (recommended).

**Recommended (Windows):** We strongly recommend using **Python 3.11** for best compatibility with prebuilt wheels for packages like numpy and pandas. If you're on Windows, install Python 3.11 and recreate your virtual environment as shown below.

**If not installed:**

- Windows (recommended): Download Python 3.11 from [python.org](https://www.python.org/downloads/release/python-311x/)

   Create a new 3.11 venv and install dependencies:

   ```powershell
   py -3.11 -m venv .venv
   .\.venv\Scripts\activate
   python -m pip install --upgrade pip setuptools wheel
   pip install -r requirements.txt
   ```

- Mac: `brew install python` or download from python.org
- Linux: `sudo apt-get install python3 python3-pip`

#### Step 4: Run Setup Script

**Mac/Linux:**

```bash
chmod +x setup.sh run.sh
./setup.sh
```

**Windows (using Git Bash or WSL):**

```bash
bash setup.sh
```

**Windows (without bash):**

```cmd
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
```

#### Step 5: Get Your SecureAI (Anthropic) API Key

1. Go to https://console.anthropic.com/
2. Sign up or log in
3. Click "API Keys" in the left sidebar
4. Click "Create Key"
5. Copy your API key
6. Keep it safe!

#### Step 6: Run the Application

**Mac/Linux:**

```bash
./run.sh
```

**Windows:**

```cmd
\.venv\Scripts\activate
streamlit run app.py
```

#### Step 7: Open Your Browser

The application will automatically open at:

```
http://localhost:8501
```

If it doesn't open automatically, click the link in your terminal.

#### Step 8: Enter Your API Key

- Look for the sidebar on the left
- Find "SecureAI API Key" input field
- Paste your API key
- Click anywhere else to confirm

**You're ready!** 🎉

---

### Method 2: Docker Installation (For Production)

#### Prerequisites:

- Docker Desktop installed ([download here](https://www.docker.com/products/docker-desktop))

#### Steps:

1. **Download all files to a folder**

2. **Open Terminal in that folder**

3. **Run Docker Compose:**

   ```bash
   docker compose up --build
   ```

4. **Open browser at:**

   ```
   http://localhost:8501
   ```

5. **Enter API key in the UI**

**That's it!** The application is running in a container.

**To stop:**

```bash
docker compose down
```

---

### Method 3: Streamlit Cloud (Public Demo)

#### Prerequisites:

- GitHub account
- Files uploaded to GitHub repository

#### Steps:

1. **Create GitHub Repository**

   ```bash
   # In your threat-modeling-tool folder:
   git init
   git add .
   git commit -m "Initial commit"

   # Create repository on GitHub, then:
   git remote add origin https://github.com/YOUR-USERNAME/threat-modeling-tool.git
   git push -u origin main
   ```

2. **Go to Streamlit Cloud**

   - Visit https://share.streamlit.io
   - Sign in with GitHub
   - Click "New app"

3. **Configure Deployment**

   - Repository: YOUR-USERNAME/threat-modeling-tool
   - Branch: main
   - Main file path: app.py
   - Click "Deploy!"

4. **Add Secrets (required)**

   In your app's Settings → Secrets, add:

   ```toml
   SECUREAI_API_KEY = "your-actual-api-key"
   ```

5. **Wait 2-3 minutes**
   Your app will be live at: `your-app-name.streamlit.app`

   Note: Streamlit Cloud automatically installs native libraries listed in `packages.txt` (Cairo, Pango, etc.) so WeasyPrint works out of the box for fully formatted PDFs.

5. **Share the URL** with your team!

---

## 🎯 **QUICK TEST (30 Seconds)**

Once the app is running:

1. **Enter API Key** (in sidebar)

2. **Fill Project Info:**

   - Project Name: "Test App"
   - Application Type: "Web Application"
   - Deployment Model: "Cloud (AWS)"
   - Business Criticality: "High"

3. **Upload a File:**

   - Any text file or image
   - Even a screenshot will work!

4. **Select Framework:**

   - Check "MITRE ATT&CK"

5. **Click "Generate Threat Assessment Report"**

6. **Wait 1-2 minutes**

7. **Download your report!**

---

## 🔧 **TROUBLESHOOTING**

### "Module not found" error

**Solution:**

```bash
pip install -r requirements.txt
```

or

```bash
pip install streamlit anthropic PyPDF2 python-docx Pillow
```

### "Port 8501 already in use"

**Solution:**

```bash
# Kill the process (Mac/Linux)
lsof -ti:8501 | xargs kill -9

# Or use a different port
streamlit run app.py --server.port=8502
```

### "Permission denied" on setup.sh

**Solution:**

```bash
chmod +x setup.sh run.sh
```

### "Python not found"

**Solution:**

- Install Python 3.9+ from python.org
- Make sure it's in your PATH
- Try `python3` instead of `python`

### API Key not working

**Solution:**

- Make sure you copied the entire key (no spaces)
- Check you have credits in your Anthropic account
- Generate a new key if needed

### Streamlit not opening automatically

**Solution:**

- Manually go to http://localhost:8501
- Check the terminal for the correct URL
- Make sure firewall isn't blocking port 8501
  py -3.11 --versionstreamlit run app.py

### Windows: build failures for numpy/pandas

If pip fails when building packages like **numpy** or **pandas** with errors mentioning "Unknown compiler" or "Failed to build", try the following steps:

1. Upgrade packaging tools (always do this first):

```bash
python -m pip install --upgrade pip setuptools wheel
```

2. Try installing pre-built binary wheels first (fast):

```bash
python -m pip install --prefer-binary --only-binary=:all: numpy==1.26.4 pandas==2.1.4 Pillow==12.1.0
```

If that succeeds, re-run `pip install -r requirements.txt`.

3. If you still see compiler errors, install the Visual Studio Build Tools:

- Download and run the installer: https://aka.ms/vs/17/release/vs_BuildTools.exe
- Select **Desktop development with C++** and complete the install
- Reboot, re-open terminal, activate your venv, then:

```bash
pip install -r requirements.txt
```

4. Alternative (recommended for scientific stacks): use Conda or Mamba to get prebuilt binaries effortlessly:

```bash
# with mamba (recommended)
mamba create -n tmt python=3.11 -y
mamba activate tmt
mamba install -y numpy pandas pillow streamlit
# then install the remaining requirements via pip (no-deps avoids re-building)
pip install -r requirements.txt --no-deps
```

5. If you want help debugging, run these and paste the outputs:

```bash
python --version
python -m pip --version
python -m pip install --upgrade pip setuptools wheel
python -m pip install --prefer-binary --only-binary=:all: numpy pandas Pillow -v
```

**Tip:** If you see an error like `Client.__init__\(\) got an unexpected keyword argument 'proxies'` when calling the Anthropic client, it's caused by an incompatible `httpx` version. Install a compatible `httpx` version in your venv:

```bash
python -m pip install httpx==0.23.3
```

Note: this repo pins `Pillow==10.4.0` to stay compatible with `streamlit==1.29.0` (which requires `pillow<11`) while still using prebuilt wheels on Windows. If you prefer a newer Pillow, consider upgrading Streamlit first.

---

## 📂 **FILE STRUCTURE EXPLANATION**

```
threat-modeling-tool/
│
├── app.py                    # 🎯 Main application (this is where the magic happens)
│                             # Contains all the UI, logic, and AI integration
│
├── requirements.txt          # 📦 Python packages needed
│
├── setup.sh                  # ⚡ Auto-setup script (Mac/Linux)
├── run.sh                    # ▶️  Quick run script (Mac/Linux)
│
├── Dockerfile                # 🐳 Docker container config
├── docker-compose.yml        # 🐳 Docker Compose setup
│
├── README.md                 # 📖 Full documentation
├── QUICKSTART.md            # ⚡ 5-minute guide
├── DEPLOYMENT.md            # 🚀 Deployment guide
├── GETTING_STARTED.md       # 📋 Overview
│
├── .streamlit/
│   └── config.toml          # 🎨 UI configuration
│
├── .env.example             # 🔑 Environment variables template
└── .gitignore              # 📝 Git ignore rules
```

---

## 💡 **WHAT TO DO AFTER INSTALLATION**

### Immediate Next Steps:

1. **Run your first assessment** (use the 30-second test above)

2. **Review the generated report**

   - See what Claude AI produces
   - Understand the format
   - Check quality

3. **Test with a real project**

   - Upload actual architecture diagrams
   - Add real documentation
   - Compare with manual assessments

4. **Share with 2-3 colleagues**
   - Get feedback
   - Identify improvements
   - Validate usefulness

### This Week:

5. **Customize the tool**

   - Update branding if needed
   - Adjust risk categories
   - Modify frameworks

6. **Create process**

   - When to use the tool
   - Who reviews reports
   - How to track findings

7. **Integrate into workflow**
   - Add to project templates
   - Include in security reviews
   - Link to JIRA/ticketing

### Next Month:

8. **Deploy to production**

   - Choose cloud platform
   - Set up authentication
   - Configure persistence

9. **Add enterprise features**

   - User management
   - Assessment history
   - Team collaboration

10. **Measure impact**
    - Time savings
    - Quality improvements
    - Team adoption

---

## 🎓 **LEARNING RESOURCES**

### To Understand the Code:

1. **app.py** - Read the comments, they explain everything
2. **README.md** - Feature overview and architecture
3. **Streamlit Docs** - https://docs.streamlit.io

### To Customize:

1. **UI Changes** - Modify the CSS in app.py (lines 20-100)
2. **Frameworks** - Update FRAMEWORKS dictionary (lines 50-80)
3. **Risk Areas** - Update RISK_AREAS dictionary (lines 82-150)
4. **Prompts** - Modify generate_threat_assessment() function

**Prompt Debugging Toggle**

- The app includes a **sidebar checkbox**: **Enable prompt debugging (show prompt preview on API errors)**. When enabled, the first ~300 characters of the **formatted** prompt will be displayed in the UI if the SecureAI API returns an error.

- **Privacy warning:** the preview can include snippets of uploaded documents or other project information. **Do not enable** this toggle when working with sensitive content or when sharing your screen.

**PDF Generation**

- The app generates a professionally formatted **PDF** of the report using `markdown` + `weasyprint` when available. If those are not available locally, the app uses a styled **ReportLab fallback** so the PDF button still appears (reduced styling) or offers a **Markdown (.md)** download.

- The generated PDF now includes a **Table of Contents**, a header (project & date), and page numbers for a professional, client-ready layout.

- The app also augments reports with **suggested authoritative references** when it detects common findings (e.g., prompt injection, privilege escalation). You can review and edit the references before downloading.

- To enable PDF output locally on Windows, install the optional Python packages and system dependencies:

  - Install Python packages in your venv:

    pip install markdown weasyprint

   - WeasyPrint requires system libraries (Cairo, Pango, GDK-PixBuf). On Windows, the simplest path is Docker (`docker compose up --build`) or follow the official Windows guidance: https://weasyprint.org/docs/

  - If you see the application return a Markdown download instead of a PDF, check the **PDF export** indicator in the sidebar (it will say which package is missing) and consult the log message shown under the Download button — it often includes the underlying Python exception (e.g., missing library or invalid environment).

- On Streamlit Cloud, native libraries listed in `packages.txt` are installed automatically during deploy — WeasyPrint works out of the box for fully formatted PDFs.

- If you prefer, you can convert the `.md` output to PDF with Pandoc or wkhtmltopdf externally.

### To Deploy:

1. **DEPLOYMENT.md** - Step-by-step for all platforms
2. **Docker Docs** - https://docs.docker.com
3. **Streamlit Cloud** - https://docs.streamlit.io/streamlit-community-cloud

---

## 📞 **GETTING HELP**

### If you get stuck:

1. **Check the troubleshooting section above**
2. **Review the error message carefully**
3. **Check Python and package versions**
4. **Try the Docker method** (fewer dependencies)
5. **Read the relevant documentation file**

### Common Issues & Solutions:

| Issue                  | Solution                                |
| ---------------------- | --------------------------------------- |
| Can't install packages | Update pip: `pip install --upgrade pip` |
| Port already in use    | Change port or kill process             |
| API key error          | Check key, check credits                |
| Slow processing        | Normal for large documents (2-5 min)    |
| Docker issues          | Restart Docker Desktop                  |

---

## ✅ **INSTALLATION CHECKLIST**

Before you start:

- [ ] Python 3.9+ installed
- [ ] pip working
- [ ] Anthropic account created
- [ ] API key obtained
- [ ] Terminal/command prompt open

After installation:

- [ ] Application runs without errors
- [ ] Browser opens to localhost:8501
- [ ] Can enter API key
- [ ] Can upload files
- [ ] Test assessment completes
- [ ] Can download report

---

## 🎉 **YOU'RE ALL SET!**

Once you've completed the installation:

✅ You have a working threat modeling tool
✅ You can generate professional assessments
✅ You can deploy anywhere (local, cloud, docker)
✅ You have complete documentation
✅ You have a scalable enterprise solution

**Next:** Run your first real threat assessment!

---

**Need help? Review the troubleshooting section or check the detailed guides in the documentation files.**

**Happy threat modeling! 🔒**

---

_Last Updated: December 2025_
