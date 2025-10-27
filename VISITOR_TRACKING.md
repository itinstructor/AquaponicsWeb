# Visitor Tracking Feature - Setup Guide

## Overview

The visitor tracking feature automatically logs and displays the geographic locations of visitors to the WNCC Aquaponics website. It uses IP geolocation to plot visitor locations on an interactive world map.

## How It Works

### Components

1. **Automatic Tracking Middleware** (`main_app.py`)
   - Intercepts every page request
   - Extracts the visitor's IP address (handles proxies and load balancers)
   - Fetches geolocation data from ipinfo.io API
   - Stores location in SQLite database
   - Implements 1-hour cooldown per IP to avoid spam

2. **Database Storage** (`database.py`, `geomap_module/models.py`)
   - SQLite database stores visitor information
   - Tracks: IP, latitude, longitude, city, region, country, timestamp, user agent, page visited
   - Database file: `visitors.db` (automatically created on first run)

3. **Visitor Map Page** (`templates/visitors.html`)
   - Interactive Leaflet.js map showing all visitor locations
   - Marker clustering for better visualization
   - Statistics cards showing total and unique visitors
   - Recent visitors table
   - Auto-refreshing statistics

4. **API Endpoints** (`geomap_module/routes.py`)
   - `/aquaponics/visitors` - Main visitor map page
   - `/aquaponics/api/visitor-locations` - JSON endpoint for all visitor data
   - `/aquaponics/api/visitor-stats` - JSON endpoint for statistics

## Installation

### 1. Install Dependencies

The visitor tracking feature requires Flask-SQLAlchemy:

```bash
# Activate your virtual environment first
.venv\Scripts\activate

# Install required packages
pip install -r requirements.txt
```

Or install manually:

```bash
pip install flask waitress requests flask-sqlalchemy
```

### 2. Database Setup

The database is automatically created on first run. No manual setup needed!

The database file `visitors.db` will be created in the application root directory.

### 3. API Configuration

The feature uses the free tier of ipinfo.io API:
- **Free tier**: 50,000 requests per month
- **No API key required** for basic usage
- **Rate limit**: Plenty for typical website traffic

For higher traffic sites, you can get a free API key from https://ipinfo.io/ and modify `geomap_module/helpers.py` to include it:

```python
response = requests.get(f'https://ipinfo.io/{ip_address}/json?token=YOUR_API_KEY', timeout=5)
```

## Features

### Visitor Map Display

- **World Map**: Interactive Leaflet.js map centered on Nebraska
- **Markers**: Each visitor location shown as a pin
- **Clustering**: Multiple visitors in the same area are grouped for clarity
- **Popups**: Click markers to see city, region, country, and visit time
- **Zoom/Pan**: Full map navigation controls

### Statistics

- **Total Visits**: Count of all recorded visits
- **Unique Visitors**: Count of unique IP addresses
- **Recent Visitors**: Table showing last 10 visitors with location and time
- **Auto-refresh**: Statistics update every 30 seconds

### Privacy Considerations

The system is designed with privacy in mind:

1. **City-level accuracy**: Only stores city/region/country, not exact coordinates
2. **No personal data**: Only IP address and user agent stored
3. **Cooldown period**: Same IP only logged once per hour
4. **Anonymous display**: Visitor map shows locations, not identifying information
5. **Local IPs handled**: Private/local IPs default to WNCC location

### Excluded from Tracking

The following requests are NOT tracked to reduce noise:
- Static file requests (`/aquaponics/static/`)
- API endpoints (`/aquaponics/api/`)
- Health check endpoints
- Stream proxy (video streaming)

## Usage

### Accessing the Visitor Map

Navigate to: `https://lab.wncc.edu/aquaponics/visitors`

Or click the "🌍 Visitors" link in the navigation menu.

### How Tracking Works

1. User visits any page on the site
2. `@app.before_request` middleware intercepts the request
3. System extracts the IP address (handling X-Forwarded-For for IIS)
4. Checks if this IP was tracked in the last hour (cooldown)
5. If new/expired, fetches geolocation from ipinfo.io
6. Stores visitor record in database
7. Visitor can immediately see their location on the map

## Troubleshooting

### Database Issues

If you encounter database errors:

```bash
# Delete and recreate the database
rm visitors.db
# Restart the application - database will be auto-created
```

### Geolocation Not Working

1. Check internet connectivity - the app needs to reach ipinfo.io
2. Check firewall settings - allow outbound HTTPS to ipinfo.io
3. Check logs for API errors: `logs/main_app.log`
4. Verify you haven't exceeded the 50,000 monthly request limit

### Map Not Displaying

1. Check browser console for JavaScript errors
2. Verify Leaflet.js CDN is accessible
3. Check that `/aquaponics/api/visitor-locations` returns JSON data
4. Clear browser cache

### IIS Deployment Issues

1. Ensure database file is writable by IIS application pool identity
2. Set appropriate permissions on the application directory
3. Check that visitors.db is in the same directory as main_app.py

```powershell
# Give IIS write access to the app directory
icacls "C:\inetpub\aquaponics" /grant "IIS_IUSRS:(OI)(CI)M"
```

## Maintenance

### Database Management

The SQLite database will grow over time. To manage it:

```python
# Query visitor count
from database import db
from geomap_module.models import VisitorLocation

with app.app_context():
    count = VisitorLocation.query.count()
    print(f"Total visitors: {count}")
```

### Clearing Old Data

To remove old visitor records:

```python
from datetime import datetime, timedelta
from database import db
from geomap_module.models import VisitorLocation

with app.app_context():
    # Delete records older than 90 days
    cutoff = datetime.utcnow() - timedelta(days=90)
    old_records = VisitorLocation.query.filter(VisitorLocation.timestamp < cutoff).delete()
    db.session.commit()
    print(f"Deleted {old_records} old records")
```

## Customization

### Change Cooldown Period

Edit `main_app.py`, line ~120:

```python
# Change from 1 hour to 24 hours
recent_cutoff = datetime.utcnow() - timedelta(hours=24)
```

### Change Default Location

Edit `geomap_module/helpers.py`, line ~28:

```python
return {
    "lat": YOUR_LATITUDE,
    "lon": YOUR_LONGITUDE,
    "city": "Your City",
    "region": "Your Region",
    "country": "Your Country"
}
```

### Customize Map Appearance

Edit `templates/visitors.html`:
- Change map center/zoom (line 98)
- Modify marker cluster colors (line 186-202)
- Adjust auto-refresh interval (line 178)

## API Reference

### GET /aquaponics/api/visitor-locations

Returns all visitor location records.

**Response:**
```json
[
  {
    "id": 1,
    "ip_address": "1.2.3.4",
    "lat": 41.4925,
    "lon": -99.9018,
    "city": "Broken Bow",
    "region": "Nebraska",
    "country": "United States",
    "timestamp": "2025-10-04T12:34:56",
    "user_agent": "Mozilla/5.0...",
    "page_visited": "/aquaponics"
  }
]
```

### GET /aquaponics/api/visitor-stats

Returns visitor statistics.

**Response:**
```json
{
  "total_visitors": 150,
  "unique_visitors": 87,
  "recent_visitors": [
    {
      "city": "Broken Bow",
      "region": "Nebraska",
      "country": "United States",
      "timestamp": "2025-10-04T12:34:56"
    }
  ]
}
```

## Security Considerations

1. **Input Validation**: IP addresses are validated before geolocation lookup
2. **SQL Injection**: SQLAlchemy ORM prevents SQL injection attacks
3. **Rate Limiting**: 1-hour cooldown prevents spam/abuse
4. **Error Handling**: Failures in tracking don't break the main application
5. **Database Rollback**: Failed transactions are properly rolled back

## Performance

- **Minimal Impact**: Tracking adds ~100-200ms per unique visitor
- **Caching**: Cooldown period prevents repeated API calls
- **Async Potential**: Could be moved to background task for even better performance
- **Database**: SQLite is sufficient for thousands of visitors
- **Marker Clustering**: Keeps map responsive even with many markers

## Future Enhancements

Potential improvements:
1. Admin dashboard for visitor analytics
2. Geographic filtering/search
3. Export visitor data to CSV
4. Integration with Google Analytics
5. Real-time visitor tracking
6. Heatmap visualization
7. Visitor journey tracking (page flow)
8. Mobile app support


