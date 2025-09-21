import os
import uuid
from datetime import datetime
from functools import wraps

from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
import requests
import jwt

# Whisper
import whisper
import tempfile

# -------------------------
# App + config
# -------------------------
app = Flask(__name__)
CORS(app)

app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev_secret_key')

database_url = os.environ.get('DATABASE_URL')
if database_url and database_url.startswith('postgres://'):
    database_url = database_url.replace('postgres://', 'postgresql://', 1)
if not database_url:
    database_url = 'sqlite:///civi_connect.db'
app.config['SQLALCHEMY_DATABASE_URI'] = database_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

UPLOAD_FOLDER = os.environ.get('UPLOAD_FOLDER', 'uploads')
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

db = SQLAlchemy(app)

# -------------------------
# Models
# -------------------------
class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False, default='User')
    email = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), default='citizen')
    department = db.Column(db.String(50))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)

class Issue(db.Model):
    __tablename__ = 'issues'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    issue_type = db.Column(db.String(50), nullable=False)
    status = db.Column(db.String(20), default='reported')
    priority = db.Column(db.String(10), default='medium')
    latitude = db.Column(db.Float, nullable=False)
    longitude = db.Column(db.Float, nullable=False)
    accuracy = db.Column(db.Float)
    address = db.Column(db.String(255))
    image_url = db.Column(db.String(255))
    reported_by = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    assigned_to = db.Column(db.Integer, db.ForeignKey('users.id'))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    resolved_at = db.Column(db.DateTime)

class IssueUpdate(db.Model):
    __tablename__ = 'issue_updates'
    id = db.Column(db.Integer, primary_key=True)
    issue_id = db.Column(db.Integer, db.ForeignKey('issues.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    update_text = db.Column(db.Text)
    status_change = db.Column(db.String(50))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

# -------------------------
# Auth decorator
# -------------------------
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token_header = request.headers.get('Authorization')
        if not token_header:
            return jsonify({'error': 'Token is missing'}), 401

        token = token_header
        if token_header.startswith('Bearer '):
            token = token_header[7:]

        try:
            payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            current_user = User.query.get(payload.get('user_id'))
            if not current_user:
                return jsonify({'error': 'Invalid token - user not found'}), 401
        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'Token expired'}), 401
        except jwt.InvalidTokenError as e:
            return jsonify({'error': 'Token is invalid', 'details': str(e)}), 401

        return f(current_user, *args, **kwargs)
    return decorated

# -------------------------
# Utilities
# -------------------------
def get_address_from_coordinates(lat, lng):
    try:
        url = f"https://nominatim.openstreetmap.org/reverse?format=jsonv2&lat={lat}&lon={lng}"
        r = requests.get(url, timeout=5, headers={'User-Agent': 'civi-connect/1.0'})
        if r.status_code == 200:
            data = r.json()
            return data.get('display_name') or f"Lat: {lat:.6f}, Lng: {lng:.6f}"
    except Exception:
        pass
    return f"Lat: {lat:.6f}, Lng: {lng:.6f}"

def token_response_for_user(user):
    payload = {
        'user_id': user.id,
        'email': user.email,
        'role': user.role,
    }
    token = jwt.encode(payload, app.config['SECRET_KEY'], algorithm='HS256')
    if isinstance(token, bytes):
        token = token.decode('utf-8')
    return token

# -------------------------
# Routes: Auth
# -------------------------
@app.route('/api/register', methods=['POST'])
def register():
    data = request.get_json() or {}
    email = data.get('email')
    password = data.get('password')
    name = data.get('name') or email.split('@')[0]

    if not email or not password:
        return jsonify({'error': 'Email and password are required'}), 400

    if User.query.filter_by(email=email).first():
        return jsonify({'error': 'Email already registered'}), 400

    user = User(name=name, email=email, password_hash=generate_password_hash(password))
    db.session.add(user)
    db.session.commit()
    return jsonify({'message': 'User registered successfully', 'user_id': user.id}), 201

@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json() or {}
    email = data.get('email')
    password = data.get('password')

    if not email or not password:
        return jsonify({'error': 'Email and password required'}), 400

    user = User.query.filter_by(email=email).first()
    if user and check_password_hash(user.password_hash, password):
        token = token_response_for_user(user)
        return jsonify({'token': token, 'user': {
            'id': user.id, 'name': user.name, 'email': user.email, 'role': user.role, 'department': user.department
        }})
    return jsonify({'error': 'Invalid credentials'}), 401

@app.route('/api/admin-login', methods=['POST'])
def admin_login():
    data = request.get_json() or {}
    if data.get('admin_id') == 'admin123' and data.get('code') == 'secure2024':
        admin_user = User.query.filter_by(email='admin@city.gov').first()
        if not admin_user:
            admin_user = User(name='Administrator', email='admin@city.gov',
                              password_hash=generate_password_hash('admin123'), role='admin')
            db.session.add(admin_user)
            db.session.commit()
        token = token_response_for_user(admin_user)
        return jsonify({'token': token, 'user': {
            'id': admin_user.id, 'name': admin_user.name, 'email': admin_user.email, 'role': admin_user.role
        }})
    return jsonify({'error': 'Invalid admin credentials'}), 401

# -------------------------
# Routes: Issues
# -------------------------
@app.route('/api/issues', methods=['POST'])
@token_required
def create_issue(current_user):
    data = request.get_json() or {}
    title = data.get('title')
    issue_type = data.get('issue_type')
    lat, lng = data.get('latitude'), data.get('longitude')

    if not title or not issue_type or lat is None or lng is None:
        return jsonify({'error': 'Title, issue_type, latitude, and longitude required'}), 400

    address = get_address_from_coordinates(lat, lng)
    issue = Issue(
        title=title,
        description=data.get('description'),
        issue_type=issue_type,
        latitude=lat,
        longitude=lng,
        accuracy=data.get('accuracy'),
        address=address,
        image_url=data.get('image_url'),
        reported_by=current_user.id
    )
    db.session.add(issue)
    db.session.commit()
    return jsonify({'message': 'Issue created successfully', 'id': issue.id}), 201

@app.route('/api/issues', methods=['GET'])
@token_required
def list_issues(current_user):
    issues = Issue.query.all()
    return jsonify([{
        'id': i.id,
        'title': i.title,
        'description': i.description,
        'issue_type': i.issue_type,
        'status': i.status,
        'priority': i.priority,
        'latitude': i.latitude,
        'longitude': i.longitude,
        'address': i.address,
        'image_url': i.image_url,
        'reported_by': i.reported_by,
        'assigned_to': i.assigned_to,
        'created_at': i.created_at.isoformat(),
        'updated_at': i.updated_at.isoformat(),
    } for i in issues])

@app.route('/api/issues/<int:issue_id>', methods=['PUT'])
@token_required
def update_issue(current_user, issue_id):
    issue = Issue.query.get_or_404(issue_id)
    data = request.get_json() or {}

    if 'status' in data:
        issue.status = data['status']
    if 'priority' in data:
        issue.priority = data['priority']
    if 'assigned_to' in data:
        issue.assigned_to = data['assigned_to']

    issue.updated_at = datetime.utcnow()
    db.session.commit()

    update = IssueUpdate(
        issue_id=issue.id,
        user_id=current_user.id,
        update_text=data.get('update_text'),
        status_change=issue.status
    )
    db.session.add(update)
    db.session.commit()

    return jsonify({'message': 'Issue updated successfully'})

@app.route('/api/issues/<int:issue_id>', methods=['DELETE'])
@token_required
def delete_issue(current_user, issue_id):
    issue = Issue.query.get_or_404(issue_id)
    db.session.delete(issue)
    db.session.commit()
    return jsonify({'message': 'Issue deleted successfully'})

# -------------------------
# Whisper STT Route
# -------------------------
@app.route('/api/transcribe', methods=['POST'])
def transcribe_audio():
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400

    file = request.files['file']
    if not file.filename:
        return jsonify({'error': 'Empty filename'}), 400

    with tempfile.NamedTemporaryFile(delete=False, suffix=".wav") as temp:
        file.save(temp.name)
        audio_path = temp.name

    try:
        model = whisper.load_model("base")  # try "small" or "tiny" for faster
        result = model.transcribe(audio_path)
        text = result.get("text", "").strip()
    except Exception as e:
        return jsonify({'error': 'Transcription failed', 'details': str(e)}), 500
    finally:
        if os.path.exists(audio_path):
            os.remove(audio_path)

    return jsonify({'text': text})

# -------------------------
# Initialization / main
# -------------------------
with app.app_context():
    db.create_all()

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True)

