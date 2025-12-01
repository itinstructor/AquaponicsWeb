import os
import sqlite3

DB_PATH = os.path.join("instance", "fish_blog.db")
if not os.path.exists(DB_PATH):
    print(f"Database not found at {DB_PATH}")
    exit(1)

conn = sqlite3.connect(DB_PATH)
cur = conn.cursor()

# Check if the photo table exists
cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='photo'")
row = cur.fetchone()
if row:
    print("✅ 'photo' table exists in fish_blog.db")
    # Show columns
    cur.execute("PRAGMA table_info(photo)")
    columns = cur.fetchall()
    print("Columns:")
    for col in columns:
        print(f"  - {col[1]} ({col[2]})")
    # Show a sample row if any
    cur.execute("SELECT * FROM photo LIMIT 1")
    sample = cur.fetchone()
    if sample:
        print("Sample row:", sample)
    else:
        print("No rows in photo table.")
else:
    print("❌ 'photo' table does NOT exist in fish_blog.db")

conn.close()