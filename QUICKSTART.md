# Quick Start Guide - Visitor Tracking

## Installation (5 minutes)

### Step 1: Install Dependencies

```powershell
# Navigate to your project directory
cd C:\inetpub\aquaponics

# Activate virtual environment
.venv\Scripts\Activate.ps1

# Install required packages
pip install flask-sqlalchemy

# Or install all from requirements.txt
pip install -r requirements.txt
```

### Step 2: Restart Application

```powershell
# Restart IIS
iisreset

# Or restart just your application pool
```

### Step 3: Verify Installation

1. Visit your website: `https://lab.wncc.edu/aquaponics`
2. Click the "🌍 Visitors" link in the navigation menu
3. You should see the visitor map page with your location!

## That's It!

The visitor tracking system is now active and will automatically log all visitors.

## What Happens Next?

- Every visitor to any page is automatically tracked (once per hour per IP)
- Their location is displayed on the visitor map
- Statistics update in real-time
- Recent visitors list shows last 10 connections

## Accessing the Visitor Map

URL: `https://lab.wncc.edu/aquaponics/visitors`

Or click: Navigation Menu → 🌍 Visitors

## Troubleshooting

### "Module not found" error?
```powershell
pip install flask-sqlalchemy
iisreset
```

### Database permission error?
```powershell
icacls "C:\inetpub\aquaponics" /grant "IIS_IUSRS:(OI)(CI)M"
```

### Map not showing locations?
- Check internet connection (needs to reach ipinfo.io)
- Check logs: `logs/main_app.log`
- Wait a few minutes for visitors to be tracked

## More Information

See `VISITOR_TRACKING.md` for comprehensive documentation.

## Quick Demo

1. Visit any page on your site
2. Go to `/aquaponics/visitors`
3. See your location appear on the map!
4. Statistics will show: 1 total visit, 1 unique visitor
5. Recent visitors table will show your visit

Enjoy tracking your website's global reach! 🌍


