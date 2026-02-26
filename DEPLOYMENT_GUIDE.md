# 🚀 Clean Deployment Guide for Render

## ✅ Issues Fixed

1. **Database URL Parsing** - Added automatic cleanup for malformed DATABASE_URL
2. **Procfile** - Updated to use FastAPI (uvicorn) instead of Streamlit
3. **Build Command** - Added database initialization to render.yaml

## 📋 Pre-Deployment Checklist

### 1. Environment Variables on Render

Go to your Render dashboard → Environment tab and set these variables:

#### Required Variables:
```bash
# Database (Neon PostgreSQL)
DATABASE_URL=postgresql://neondb_owner:npg_0z7RjmUYAPyT@ep-royal-sea-aelsyp87-pooler.c-2.us-east-2.aws.neon.tech/neondb?sslmode=require

# Anthropic AI
ANTHROPIC_API_KEY=your_actual_anthropic_api_key_here

# Security
SECRET_KEY=auto-generated-by-render-or-create-your-own-secret-key-here
ENVIRONMENT=production

# CORS (Update with your actual frontend URL)
ALLOWED_ORIGINS=https://threat-modeling-ui.onrender.com,https://your-frontend-domain.com
```

⚠️ **IMPORTANT**: Make sure DATABASE_URL does NOT have:
- ❌ `psql ` at the beginning
- ❌ Single quotes `'` around it
- ❌ Any command prefixes

✅ **Correct format:**
```
postgresql://user:password@host/database?sslmode=require
```

❌ **Wrong format:**
```
psql 'postgresql://user:password@host/database?sslmode=require'
```

### 2. Files Updated

The following files have been updated for clean deployment:

- ✅ **database.py** - Now automatically cleans malformed DATABASE_URL
- ✅ **Procfile** - Set to run FastAPI backend
- ✅ **render.yaml** - Added database initialization to build command

### 3. Deployment Steps

#### Option A: Deploy via Render Dashboard

1. **Connect Repository**
   - Go to [Render Dashboard](https://dashboard.render.com)
   - Click "New +" → "Web Service"
   - Connect your GitHub repository

2. **Configure Service**
   - **Name**: threat-modeling-api
   - **Environment**: Python 3
   - **Build Command**: `pip install -r requirements.txt && python init_db.py`
   - **Start Command**: `uvicorn api:app --host 0.0.0.0 --port $PORT`
   - **Plan**: Free

3. **Set Environment Variables**
   - Add all the variables listed above in the Environment tab

4. **Deploy**
   - Click "Create Web Service"
   - Wait for deployment to complete

#### Option B: Deploy via render.yaml

1. **Push changes to Git**
   ```bash
   git add .
   git commit -m "Fix deployment configuration"
   git push origin main
   ```

2. **Create Blueprint on Render**
   - Go to Render Dashboard
   - Click "New +" → "Blueprint"
   - Select your repository
   - Render will auto-detect render.yaml

3. **Set Secret Environment Variables**
   - `ANTHROPIC_API_KEY`
   - `DATABASE_URL`
   - Other secrets not in render.yaml

4. **Deploy**
   - Click "Apply" to deploy all services

## 🔍 Verify Deployment

### Health Check
Once deployed, test these endpoints:

```bash
# Health check
curl https://your-app.onrender.com/health

# API docs
https://your-app.onrender.com/api/docs
```

### Expected Response:
```json
{
  "status": "healthy",
  "database": "connected",
  "version": "2.0.0"
}
```

## 🐛 Troubleshooting

### Issue: "Could not parse SQLAlchemy URL"
**Solution**: Check DATABASE_URL environment variable
- Remove `psql ` prefix if present
- Remove quotes around the URL
- Ensure format: `postgresql://...` not `postgres://...`

### Issue: "No module named 'anthropic'"
**Solution**: Build command not running properly
- Verify build command: `pip install -r requirements.txt`
- Check build logs for errors

### Issue: "No tables found"
**Solution**: Database not initialized
- Add `&& python init_db.py` to build command
- Or manually run: `python init_db.py` after first deploy

### Issue: CORS errors from frontend
**Solution**: Update ALLOWED_ORIGINS
- Add your frontend URL to ALLOWED_ORIGINS environment variable
- Format: `https://frontend1.com,https://frontend2.com`

## 📊 Monitoring

### Check Logs
```bash
# Via Render dashboard
Dashboard → Your Service → Logs tab
```

### Common Log Patterns to Watch For:

✅ **Successful startup:**
```
INFO:     Started server process
INFO:     Waiting for application startup.
INFO:     Application startup complete.
INFO:     Uvicorn running on http://0.0.0.0:10000
```

❌ **Database connection error:**
```
sqlalchemy.exc.OperationalError: could not connect to server
```
→ Check DATABASE_URL

❌ **Import errors:**
```
ModuleNotFoundError: No module named 'xyz'
```
→ Check requirements.txt and rebuild

## 🔐 Security Checklist

- [ ] SECRET_KEY is set and unique
- [ ] ANTHROPIC_API_KEY is set and valid
- [ ] DATABASE_URL uses SSL (`?sslmode=require`)
- [ ] ALLOWED_ORIGINS only includes your domains
- [ ] No sensitive data in git repository
- [ ] Environment variables are marked as "secret" on Render

## 📝 Post-Deployment Tasks

1. **Create Admin User**
   ```bash
   # Via Render Shell or local connection to prod DB
   python create_admin.py
   ```

2. **Test API**
   - Visit `/api/docs`
   - Test authentication endpoints
   - Test threat assessment creation

3. **Monitor Usage**
   - Check Render metrics
   - Review application logs
   - Set up alerts if needed

## 🎯 Next Steps

1. **Frontend Deployment**
   - Deploy React frontend as static site
   - Update VITE_API_URL to point to your backend
   - Update ALLOWED_ORIGINS to include frontend URL

2. **Custom Domain** (Optional)
   - Add custom domain in Render
   - Update environment variables with new domain
   - Configure DNS records

3. **Scaling** (When needed)
   - Upgrade from Free plan for always-on service
   - Increase database connection pool
   - Add Redis for caching (optional)

## 📞 Support Resources

- [Render Documentation](https://render.com/docs)
- [Neon PostgreSQL Docs](https://neon.tech/docs)
- [FastAPI Deployment](https://fastapi.tiangolo.com/deployment/)

---

**Last Updated**: February 3, 2026
**Status**: Ready for deployment ✅
