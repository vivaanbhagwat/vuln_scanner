
import sys
import os
sys.path.append(os.getcwd())
from app import create_app
from extensions import db
from models.user import User

app = create_app()
with app.app_context():
    user = User.query.filter_by(email='viv08.bhagwat@gmail.com').first()
    if user:
        print(f"Updating password for user: {user.username}")
        user.set_password('viv.bhagwat@0402')
        db.session.commit()
        print("Password updated successfully.")
    else:
        print("Admin user not found in database.")
