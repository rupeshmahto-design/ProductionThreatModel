# EnterpriseUI - React Frontend Setup

## 🎨 Modern React/TypeScript UI

This is the frontend for the AssurePro AI Project Assurance Platform, built with:

- **React 18** with TypeScript
- **Vite** for fast development and building
- **Tailwind CSS** for styling (via CDN)
- **Recharts** for data visualization
- **Font Awesome** icons

## 📁 Project Structure

```
EnterpriseUI/
├── components/           # React components
│   ├── AdminDashboard.tsx
│   ├── FileUpload.tsx
│   ├── Login.tsx
│   ├── Register.tsx
│   ├── ProfessionalReport.tsx
│   ├── ReportDashboard.tsx
│   ├── ReportHistory.tsx
│   └── Sidebar.tsx
├── context/             # React Context providers
│   └── AuthContext.tsx
├── App.tsx              # Main application component
├── index.tsx            # Entry point
├── index.html           # HTML template
├── types.ts             # TypeScript type definitions
├── constants.ts         # Configuration constants
├── vite.config.ts       # Vite configuration
├── tsconfig.json        # TypeScript configuration
├── tailwind.config.js   # Tailwind CSS configuration
└── package.json         # Dependencies

Backend (Python/FastAPI):
├── api.py              # FastAPI backend
├── app.py              # Streamlit app (legacy)
├── auth.py             # Authentication
├── database.py         # Database configuration
└── models.py           # Database models
```

## 🚀 Quick Start

### Prerequisites

- Node.js 18+ and npm (or pnpm/yarn)
- Python 3.11+
- PostgreSQL database

### 1. Install Frontend Dependencies

```bash
npm install
# or
pnpm install
# or
yarn install
```

### 2. Configure Environment

Create a `.env` file in the root directory:

```env
VITE_API_URL=http://localhost:8000
```

### 3. Start Development Servers

**Terminal 1 - Backend (FastAPI):**
```bash
# Make sure you have Python dependencies installed
pip install -r requirements.txt

# Run the FastAPI backend
uvicorn api:app --reload --port 8000
```

**Terminal 2 - Frontend (Vite):**
```bash
npm run dev
# or
pnpm dev
```

The app will be available at:
- Frontend: http://localhost:3000
- Backend API: http://localhost:8000
- API Docs: http://localhost:8000/docs

## 🔑 Features

### 1. **Authentication & Authorization**
   - User registration and login
   - JWT token-based authentication
   - Role-based access control (User/Admin)

### 2. **Project Upload & Analysis**
   - Upload multiple project documents
   - Automatic document categorization
   - Support for various file types

### 3. **AI-Powered Report Generation**
   - Integrates with Anthropic Claude API
   - Comprehensive project assurance analysis
   - Gap analysis and recommendations

### 4. **Interactive Dashboards**
   - Executive summary cards
   - Charts and visualizations (Recharts)
   - Benefits realization tracking
   - Risk analysis

### 5. **Professional Report Export**
   - Print-ready PDF format
   - Custom branding and styling
   - Document registry
   - Executive summary

### 6. **Report History**
   - View past reports
   - Reload and review
   - Track assurance over time

### 7. **Admin Dashboard**
   - User management
   - Audit logs
   - System monitoring

## 🛠️ Development

### Build for Production

```bash
npm run build
```

This creates an optimized production build in the `dist/` folder.

### Preview Production Build

```bash
npm run preview
```

### Linting

```bash
npm run lint
```

## 🎨 Customization

### Branding

Edit [App.tsx](App.tsx) to customize:
- Company logo (line ~221)
- Header title "AssurePro AI"
- Color scheme (Tailwind classes)

### API Configuration

Edit [constants.ts](constants.ts):
- `API_BASE_URL` - Backend API URL
- Project stages, frameworks, etc.

### Styling

The app uses Tailwind CSS via CDN (configured in [index.html](index.html)). 

For custom styles, edit:
- Tailwind config: [tailwind.config.js](tailwind.config.js)
- Global styles in [index.html](index.html) `<style>` tag

## 📊 Charts & Visualizations

The app uses **Recharts** for:
- Pie charts (Gap analysis by severity)
- Bar charts (Benefits readiness scores)
- Custom dashboard metrics

## 🔐 Security

- API keys stored in browser localStorage (configurable via Sidebar)
- JWT tokens for authentication
- Secure API communication
- Input validation

## 🐛 Troubleshooting

### "Failed to fetch" errors
- Ensure backend is running on port 8000
- Check CORS settings in `api.py`
- Verify `.env` file has correct API URL

### TypeScript errors
- Run `npm install` to ensure dependencies are installed
- Check `tsconfig.json` configuration

### Styling issues
- Ensure Tailwind CSS CDN is loaded (check browser console)
- Clear browser cache
- Verify Tailwind config in `tailwind.config.js`

## 📦 Deployment

### Frontend (Vite/React)
- Vercel, Netlify, or any static hosting
- Build with `npm run build`
- Deploy `dist/` folder

### Backend (FastAPI)
- Heroku, Railway, Render, or AWS
- Set environment variables
- Run with `uvicorn api:app --host 0.0.0.0 --port $PORT`

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

## 📄 License

[Add your license information]

## 🆘 Support

For issues or questions:
- Check the [troubleshooting section](#-troubleshooting)
- Review FastAPI docs at http://localhost:8000/docs
- Open an issue on GitHub

---

**Built with ❤️ using React, TypeScript, and Claude AI**
