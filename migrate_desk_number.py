# migrate_desk_number.py - Add desk_number field to DealerboardTurret table

from flask import Flask
from flask_sqlalchemy import SQLAlchemy
import os

# Initialize Flask app with same config as your main app
app = Flask(__name__)
basedir = os.path.abspath(os.path.dirname(__file__))
instance_path = os.path.join(basedir, 'instance')
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{os.path.join(instance_path, "telephony.db")}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

def add_desk_number_column():
    """Add desk_number column to dealerboard_turret table"""
    with app.app_context():
        try:
            # Add the new column using the updated SQLAlchemy syntax
            with db.engine.connect() as connection:
                connection.execute(db.text('ALTER TABLE dealerboard_turret ADD COLUMN desk_number VARCHAR(50)'))
                connection.commit()
            print("✅ Successfully added desk_number column to dealerboard_turret table")
        except Exception as e:
            if "duplicate column name" in str(e).lower() or "already exists" in str(e).lower():
                print("ℹ️  desk_number column already exists")
            else:
                print(f"❌ Error adding desk_number column: {e}")

if __name__ == '__main__':
    add_desk_number_column()