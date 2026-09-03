# simple_init_db.py
# A simple script to initialize the database

from datetime import datetime
import os
print("Importing Flask...")
from flask import Flask
print("Importing SQLAlchemy...")
from flask_sqlalchemy import SQLAlchemy
print("Importing LoginManager...")
from flask_login import LoginManager, UserMixin
print("Importing werkzeug...")
from werkzeug.security import generate_password_hash

# Print current directory for debugging
print(f"Current working directory: {os.path.abspath('.')}")

# Initialize the Flask application
print("Creating Flask app...")
app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-change-in-production'

# Database configuration - keeping it simple
print("Configuring database...")
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///telephony.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ECHO'] = True  # Print SQL queries for debugging

# Initialize database
print("Initializing database...")
db = SQLAlchemy(app)

# Initialize login manager
print("Setting up login manager...")
login_manager = LoginManager()
login_manager.init_app(app)

# Define models
print("Defining models...")

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='user')
    
    def is_admin(self):
        return self.role == 'admin'

class DDINumber(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ddi_number = db.Column(db.String(12), unique=True, nullable=False)  # 12 digit number, format 6xxxxxxxxxxx
    username = db.Column(db.String(100))  # LineName from import
    cisco_cluster = db.Column(db.String(100))
    bt_system = db.Column(db.String(50))  # Dropdown: UK, REM, France, Germany, Turkey, Hong Kong, NEA, SEA, Korea, Indonesia, India, Americas, China
    location = db.Column(db.String(50))  # Dropdown: UK, Spain, Czech Rep, Poland, Italy, Israel, France, Germany, Turkey, Hong Kong, Japan, Taiwan, Singapore, Philippines, Malaysia, Thailand, Korea, Indonesia, India, USA, Mexico, Chile, Brazil, China
    status = db.Column(db.String(20), default='Active')  # Active/Spare
    date_spare = db.Column(db.DateTime, nullable=True)  # Date when marked as spare
    date_created = db.Column(db.DateTime, default=datetime.utcnow)
    last_updated = db.Column(db.DateTime, default=datetime.utcnow)
    last_change = db.Column(db.String(200))  # Description of last change

class PrivateWire(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    record_no = db.Column(db.String(50), unique=True)
    location = db.Column(db.String(50))
    dc_locale = db.Column(db.String(100))
    vega_port = db.Column(db.String(50))
    channel = db.Column(db.String(50))
    bearer_no = db.Column(db.String(50))
    circuit_no = db.Column(db.String(50))
    back_up_bearer = db.Column(db.String(100))
    cluster_name = db.Column(db.String(100))
    tpo_name = db.Column(db.String(100))
    vega_hostname = db.Column(db.String(100))
    back_up_vega_gw = db.Column(db.String(100))
    vendor = db.Column(db.String(100))
    pw_type = db.Column(db.String(50))  # Editable
    btt_slot = db.Column(db.String(50))
    aor = db.Column(db.String(50))
    a_or_b = db.Column(db.String(10))  # Editable
    dedicated_country = db.Column(db.String(50))  # Editable
    hsbc_main_user = db.Column(db.String(100))  # Editable
    employee_id = db.Column(db.String(50))  # Editable
    private_public = db.Column(db.String(20))  # Editable
    line_label = db.Column(db.String(100))  # Editable
    company_name = db.Column(db.String(100))  # Editable
    company_contact = db.Column(db.String(100))  # Editable
    company_email = db.Column(db.String(100))  # Editable
    vr_yn = db.Column(db.String(10))  # Editable
    snow_ref = db.Column(db.String(50))  # Editable
    date_created = db.Column(db.DateTime, default=datetime.utcnow)
    last_updated = db.Column(db.DateTime, default=datetime.utcnow)
    last_change = db.Column(db.String(200))

class DealerboardTurret(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    mac_address = db.Column(db.String(50), unique=True)  # From Name in import
    ip_address = db.Column(db.String(50))  # From ipaddress in import
    zone = db.Column(db.String(50))  # From zone in import
    firmware_version = db.Column(db.String(50))  # From firmwareversion in import
    model = db.Column(db.String(50))  # From model in import
    country = db.Column(db.String(50))  # Dropdown list of countries
    office = db.Column(db.String(100))
    desk_location = db.Column(db.String(100))
    date_created = db.Column(db.DateTime, default=datetime.utcnow)
    last_updated = db.Column(db.DateTime, default=datetime.utcnow)
    last_change = db.Column(db.String(200))

def init_db():
    print("Starting database initialization function...")
    with app.app_context():
        print("Creating tables...")
        db.create_all()
        
        print("Adding admin user...")
        # Check if admin user already exists
        if not User.query.filter_by(username='admin').first():
            admin_user = User(
                username='admin',
                password=generate_password_hash('admin'),
                role='admin'
            )
            db.session.add(admin_user)
        
        print("Adding regular user...")
        # Check if regular user already exists
        if not User.query.filter_by(username='user').first():
            regular_user = User(
                username='user',
                password=generate_password_hash('user'),
                role='user'
            )
            db.session.add(regular_user)
        
        # Add sample data only if tables are empty
        if DDINumber.query.count() == 0:
            print("Adding sample DDI numbers...")
            ddi1 = DDINumber(
                ddi_number='612345678901',
                username='John Doe',
                cisco_cluster='Cluster A',
                bt_system='UK',
                location='UK',
                status='Active',
                last_change='Initial creation'
            )
            db.session.add(ddi1)
        
        if PrivateWire.query.count() == 0:
            print("Adding sample private wire...")
            pw1 = PrivateWire(
                record_no='PW001',
                location='UK',
                dc_locale='London',
                vega_port='Port1',
                channel='Channel1',
                bearer_no='Bearer1',
                circuit_no='Circuit1',
                back_up_bearer='Backup1',
                cluster_name='Cluster1',
                tpo_name='TPO1',
                vega_hostname='Vega1',
                back_up_vega_gw='BackupGW1',
                vendor='Vendor1',
                pw_type='Type1',
                btt_slot='Slot1',
                aor='AOR1',
                a_or_b='A',
                dedicated_country='UK',
                hsbc_main_user='User1',
                employee_id='E001',
                private_public='Private',
                line_label='Label1',
                company_name='Company1',
                company_contact='Contact1',
                company_email='contact1@example.com',
                vr_yn='Y',
                snow_ref='SNOW001',
                last_change='Initial creation'
            )
            db.session.add(pw1)
        
        if DealerboardTurret.query.count() == 0:
            print("Adding sample turret...")
            turret1 = DealerboardTurret(
                mac_address='AA:BB:CC:DD:EE:FF',
                ip_address='192.168.1.100',
                zone='Zone1',
                firmware_version='1.0.0',
                model='Model1',
                country='UK',
                office='London Office',
                desk_location='Desk 101',
                last_change='Initial creation'
            )
            db.session.add(turret1)
        
        print("Committing changes...")
        db.session.commit()
        print("Database initialized successfully!")

if __name__ == '__main__':
    print("Running database initialization...")
    try:
        init_db()
        print("Database initialization completed successfully.")
    except Exception as e:
        print(f"Error during database initialization: {str(e)}")
        import traceback
        traceback.print_exc()