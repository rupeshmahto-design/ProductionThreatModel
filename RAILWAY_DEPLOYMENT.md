# Railway Deployment Guide

Railway is a better alternative to Render + Neon with built-in PostgreSQL and simpler setup.

## Why Railway?

✅ **Built-in PostgreSQL** - No external database service needed  
✅ **No cold starts** on hobby plan ($5/mo)  
✅ **Better free tier** - $5 credit monthly  
✅ **Simpler setup** - One-click database provisioning  
✅ **More reliable** - Better uptime than Render free tier  

## Quick Deployment Steps

### 1. Create Railway Account
1. Go to [railway.app](https://railway.app)
2. Sign up with GitHub
3. Verify your account

### 2. Deploy Backend API

#### Option A: Deploy from GitHub (Recommended)
```bash
# Push your code to GitHub first
git add .
git commit -m "Prepare for Railway deployment"
git push
```

1. Click **"New Project"** in Railway
2. Select **"Deploy from GitHub repo"**
3. Choose your repository
4. Railway will auto-detect Python and start building

#### Option B: Deploy with Railway CLI
```bash
# Install Railway CLI
npm install -g @railway/cli

# Login
railway login

# Initialize project
railway init

# Deploy
railway up
```

### 3. Add PostgreSQL Database

1. In your Railway project dashboard, click **"+ New"**
2. Select **"Database"** → **"PostgreSQL"**
3. Railway automatically creates `DATABASE_URL` variable
4. Your app will connect automatically!

### 4. Set Environment Variables

In Railway dashboard, go to your service → **Variables** tab:

```env
ANTHROPIC_API_KEY=your_anthropic_key_here
SECRET_KEY=generate_a_strong_random_key
ENVIRONMENT=production
ALLOWED_ORIGINS=https://your-frontend-domain.railway.app
```

**Generate SECRET_KEY:**
```python
import secrets
print(secrets.token_urlsafe(32))
```

### 5. Deploy Frontend (Optional - Separate Service)

#### Using Vite/React:
1. Create new service in same Railway project
2. Set build command: `npm install && npm run build`
3. Set start command: `npx serve -s dist -l $PORT`
4. Add environment variable:
   ```
   VITE_API_URL=https://your-backend.railway.app
   ```

## Environment Variables Reference

### Backend Service (api.py)
| Variable | Required | Description |
|----------|----------|-------------|
| `DATABASE_URL` | Auto-set | PostgreSQL connection (auto-created) |
| `ANTHROPIC_API_KEY` | Yes | Your Claude API key |
| `SECRET_KEY` | Yes | JWT signing key |
| `ENVIRONMENT` | No | Set to "production" |
| `ALLOWED_ORIGINS` | No | Frontend URL for CORS |

### Frontend Service (React)
| Variable | Required | Description |
|----------|----------|-------------|
| `VITE_API_URL` | Yes | Backend API URL |

## Verify Deployment

1. **Check API health:**
   ```bash
   curl https://your-app.railway.app/api/health
   ```

2. **Check database connection:**
   ```bash
   curl https://your-app.railway.app/api/health/db
   ```

3. **View logs:**
   - Go to Railway dashboard
   - Click on your service
   - View **Logs** tab

## Database Migrations

Railway automatically runs `init_db.py` during build. For manual migrations:

```bash
# Using Railway CLI
railway run alembic upgrade head

# Or connect to Railway shell
railway shell
python run_migration.py
```

## Pricing

### Free Tier
- **$5 credit** per month
- ~100 hours of service runtime
- Good for testing

### Hobby Plan ($5/month)
- **$5 credit** + usage billing
- No sleeping
- ~500GB outbound bandwidth
- Perfect for production

### Pro Plan ($20/month)
- Priority support
- Higher limits
- Team collaboration

## Troubleshooting

### Build Fails
```bash
# Check nixpacks.toml is present
# Verify requirements.txt has all dependencies
```

### Database Connection Issues
```bash
# Verify DATABASE_URL is set
railway variables

# Test connection
railway run python -c "from database import engine; print(engine.url)"
```

### Port Issues
Railway automatically sets `$PORT` variable. Ensure your app uses it:
```python
# api.py should use:
port = int(os.getenv("PORT", 8000))
```

### Frontend Can't Connect to Backend
- Check `ALLOWED_ORIGINS` in backend includes frontend URL
- Verify `VITE_API_URL` points to backend URL
- Check CORS settings in [api.py](api.py)

## Advanced: Custom Domain

1. Go to service **Settings** → **Networking**
2. Click **"Generate Domain"** or **"Custom Domain"**
3. Add your domain
4. Update DNS records as shown

## Alternative: All-in-One Deployment

For simpler setup, serve both API and frontend from one service:

```bash
# Build frontend
cd frontend && npm run build && cd ..

# Serve with FastAPI
# api.py already configured to serve static files
```

Set start command:
```bash
uvicorn api:app --host 0.0.0.0 --port $PORT
```

## Comparison with Other Platforms

| Feature | Railway | Render | Fly.io | Heroku |
|---------|---------|--------|--------|--------|
| Free tier | $5/mo credit | 750 hrs/mo | 3 VMs free | None |
| Cold starts | No (paid) | Yes (free) | No | No |
| DB included | ✅ | ❌ | ✅ | ✅ |
| Setup time | 5 min | 15 min | 10 min | 5 min |
| Reliability | ⭐⭐⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ |

## Support

- [Railway Docs](https://docs.railway.app)
- [Railway Discord](https://discord.gg/railway)
- [Railway Status](https://status.railway.app)

---

**Need help?** Check the logs in Railway dashboard or reach out on their Discord community.
