
import sys
import os
sys.path.append(os.getcwd())
from app import create_app
from extensions import db
from models.user import User

app = create_app()
with app.app_context():
    users = User.query.all()
    print("Users in database:")
    for user in users:
        print(f"ID: {user.id}, Username: {user.username}, Email: {user.email}, Role: {user.role}")
