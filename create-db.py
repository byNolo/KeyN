from auth_server.app import db, create_app

# Create the Flask application context
app = create_app()

with app.app_context():
    # Create all database tables
    db.create_all()
    print("Databases created successfully!")
