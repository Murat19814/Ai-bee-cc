"""
Database initialization script
Run this before starting the main application
"""
from app import app, db, create_initial_data

with app.app_context():
    print("Creating database tables...")
    db.create_all()
    print("Tables created!")
    
    print("Creating initial data...")
    create_initial_data()
    print("Initial data created!")
    
    # Verify tables
    from sqlalchemy import inspect
    inspector = inspect(db.engine)
    tables = inspector.get_table_names()
    print(f"\nCreated {len(tables)} tables:")
    for t in tables:
        print(f"  - {t}")

