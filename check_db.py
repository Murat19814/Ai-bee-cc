import sqlite3
import os

db_path = 'callcenter.db'
print(f"Database exists: {os.path.exists(db_path)}")

if os.path.exists(db_path):
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # List all tables
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
    tables = cursor.fetchall()
    print(f"\nTables ({len(tables)}):")
    for t in tables:
        print(f"  - {t[0]}")
    
    # Check ai_settings columns
    cursor.execute("PRAGMA table_info(ai_settings)")
    columns = cursor.fetchall()
    print(f"\nai_settings columns ({len(columns)}):")
    for col in columns:
        print(f"  {col[1]} ({col[2]})")
    
    conn.close()
else:
    print("Database not found")

