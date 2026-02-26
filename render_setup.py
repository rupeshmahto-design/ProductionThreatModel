#!/usr/bin/env python3
"""
Quick script to display your Render environment variable configuration
Copy and paste these into Render Dashboard → Environment tab
"""

print("""
╔══════════════════════════════════════════════════════════════════╗
║       RENDER ENVIRONMENT VARIABLES CONFIGURATION                  ║
╚══════════════════════════════════════════════════════════════════╝

Copy these environment variables to your Render Dashboard:
Dashboard → Your Web Service → Environment Tab → Add Environment Variable

⚠️  IMPORTANT: Remove the 'psql ' prefix and quotes from DATABASE_URL!

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

1. DATABASE_URL (Type: Secret)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

   Key:   DATABASE_URL
   Value: postgresql://neondb_owner:npg_0z7RjmUYAPyT@ep-royal-sea-aelsyp87-pooler.us-east-2.aws.neon.tech/neondb?sslmode=require

   ✅ CORRECT format (use this):
      postgresql://neondb_owner:password@host/database?sslmode=require

   ❌ WRONG format (don't use):
      psql 'postgresql://neondb_owner:password@host/database?sslmode=require'

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

2. ANTHROPIC_API_KEY (Type: Secret)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

   Key:   ANTHROPIC_API_KEY
   Value: sk-ant-api03-your-actual-api-key-here

   📝 Get your API key from: https://console.anthropic.com/settings/keys

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

3. SECRET_KEY (Type: Secret - Auto-generate or use custom)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

   Key:   SECRET_KEY
   Value: Click "Generate" button on Render
          OR use a custom 32+ character random string

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

4. ENVIRONMENT (Type: Plain)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

   Key:   ENVIRONMENT
   Value: production

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

5. ALLOWED_ORIGINS (Type: Plain)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

   Key:   ALLOWED_ORIGINS
   Value: https://threat-modeling-ui.onrender.com,http://localhost:5173

   📝 Update with your actual frontend URL after deployment
      Format: comma-separated list of allowed origins

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


📋 DEPLOYMENT STEPS:

1. Fix DATABASE_URL on Render (remove 'psql ' prefix)
   
2. Set all environment variables above

3. Commit and push your code:
   git add .
   git commit -m "Fix deployment configuration"
   git push origin main

4. Trigger manual deploy on Render or wait for auto-deploy

5. Verify deployment:
   - Check https://your-app.onrender.com/health
   - Visit https://your-app.onrender.com/api/docs

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

🔗 USEFUL LINKS:

- Render Dashboard: https://dashboard.render.com
- Neon Database: https://console.neon.tech
- Anthropic Console: https://console.anthropic.com
- API Documentation: https://your-app.onrender.com/api/docs

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

✅ Files have been updated with auto-cleanup for DATABASE_URL
✅ Procfile configured for FastAPI backend
✅ render.yaml includes database initialization
✅ Health check endpoints added

You're ready to deploy! 🚀

""")
