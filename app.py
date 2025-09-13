import os
import uuid
from datetime import datetime, timedelta
from functools import wraps

from flask import Flask, request, jsonify, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import requests
import jwt
from sqlalchemy import func

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
        except Exception as e:
            return jsonify({'error': 'Token decode error', 'details': str(e)}), 401

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
@app.route('/api/issues', methods=['GET'])
def get_issues_public():
    """ Public: anyone can view issues """
    query = Issue.query
    user_id = request.args.get('user_id')
    status = request.args.get('status')
    search = request.args.get('search')

    if user_id:
        query = query.filter_by(reported_by=int(user_id))
    if status:
        query = query.filter_by(status=status)
    if search:
        query = query.filter((Issue.title.contains(search)) | (Issue.description.contains(search)))

    issues = query.order_by(Issue.created_at.desc()).all()
    issues_data = []
    for i in issues:
        issues_data.append({
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
            'created_at': i.created_at.isoformat(),
            'updated_at': i.updated_at.isoformat() if i.updated_at else None
        })
    return jsonify({'issues': issues_data, 'total': len(issues_data)})

@app.route('/api/issues', methods=['POST'])
@token_required
def create_issue(current_user):
    # same as before (kept secure for logged-in users)
    if request.content_type and 'multipart/form-data' in request.content_type:
        title = request.form.get('title')
        description = request.form.get('description')
        issue_type = request.form.get('issue_type')
        latitude = request.form.get('latitude')
        longitude = request.form.get('longitude')
        accuracy = request.form.get('accuracy')
    else:
        data = request.get_json() or {}
        title = data.get('title')
        description = data.get('description')
        issue_type = data.get('issue_type')
        latitude = data.get('latitude')
        longitude = data.get('longitude')
        accuracy = data.get('accuracy')

    if not title or not issue_type or latitude is None or longitude is None:
        return jsonify({'error': 'Missing required fields (title, issue_type, latitude, longitude)'}), 400

    image_url = None
    if 'image' in request.files:
        file = request.files['image']
        if file and file.filename:
            ext = file.filename.rsplit('.', 1)[-1].lower()
            filename = f"{uuid.uuid4().hex}.{ext}"
            safe_name = secure_filename(filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], safe_name)
            file.save(filepath)
            image_url = f"/uploads/{safe_name}"

    try:
        lat = float(latitude)
        lng = float(longitude)
        address = get_address_from_coordinates(lat, lng)
    except Exception:
        address = None

    issue = Issue(
        title=title,
        description=description,
        issue_type=issue_type,
        latitude=float(latitude),
        longitude=float(longitude),
        accuracy=float(accuracy) if accuracy else None,
        address=address,
        image_url=image_url,
        reported_by=current_user.id
    )
    db.session.add(issue)
    db.session.commit()
    return jsonify({'message': 'Issue created', 'issue_id': issue.id}), 201

@app.route('/api/issues/<int:issue_id>', methods=['PUT'])
@token_required
def update_issue(current_user, issue_id):
    issue = Issue.query.get_or_404(issue_id)
    data = request.get_json() or {}

    if current_user.role != 'admin' and issue.reported_by != current_user.id:
        return jsonify({'error': 'Unauthorized'}), 403

    old_status = issue.status
    new_status = data.get('status', issue.status)
    issue.status = new_status
    issue.priority = data.get('priority', issue.priority)

    if new_status == 'resolved' and old_status != 'resolved':
        issue.resolved_at = datetime.utcnow()

    if current_user.role == 'admin' and 'assigned_to' in data:
        issue.assigned_to = data.get('assigned_to')

    if old_status != new_status:
        update = IssueUpdate(issue_id=issue.id, user_id=current_user.id,
                             update_text=data.get('update_text'), status_change=f"{old_status} -> {new_status}")
        db.session.add(update)

    db.session.commit()
    return jsonify({'message': 'Issue updated'})

@app.route('/api/issues/<int:issue_id>', methods=['DELETE'])
@token_required
def delete_issue(current_user, issue_id):
    issue = Issue.query.get_or_404(issue_id)
    if current_user.role != 'admin':
        return jsonify({'error': 'Unauthorized'}), 403

    if issue.image_url and issue.image_url.startswith('/uploads/'):
        filename = issue.image_url.split('/')[-1]
        try:
            os.remove(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        except Exception:
            pass

    IssueUpdate.query.filter_by(issue_id=issue.id).delete()
    db.session.delete(issue)
    db.session.commit()
    return jsonify({'message': 'Issue deleted'})

# -------------------------
# Admin stats (now PUBLIC)
# -------------------------
@app.route('/api/admin/stats', methods=['GET'])
def get_admin_stats_public():
    total_issues = Issue.query.count()
    pending_issues = Issue.query.filter(Issue.status.in_(['reported', 'acknowledged'])).count()
    in_progress_issues = Issue.query.filter_by(status='in_progress').count()
    resolved_issues = Issue.query.filter_by(status='resolved').count()

    week_ago = datetime.utcnow() - timedelta(days=7)
    recent_issues = Issue.query.filter(Issue.created_at >= week_ago).count()

    issue_types = db.session.query(Issue.issue_type, func.count(Issue.id)).group_by(Issue.issue_type).all()

    return jsonify({
        'total_issues': total_issues,
        'pending_issues': pending_issues,
        'in_progress_issues': in_progress_issues,
        'resolved_issues': resolved_issues,
        'recent_issues': recent_issues,
        'issue_types': dict(issue_types),
        'response_time_avg': 2.3
    })

# -------------------------
# Issue updates / uploads
# -------------------------
@app.route('/api/issues/<int:issue_id>/updates', methods=['GET'])
def get_issue_updates_public(issue_id):
    updates = IssueUpdate.query.filter_by(issue_id=issue_id).order_by(IssueUpdate.created_at.desc()).all()
    updates_data = []
    for u in updates:
        user = User.query.get(u.user_id)
        updates_data.append({
            'id': u.id,
            'update_text': u.update_text,
            'status_change': u.status_change,
            'created_at': u.created_at.isoformat(),
            'user_name': user.name if user else 'Unknown'
        })
    return jsonify({'updates': updates_data})

@app.route('/uploads/<path:filename>', methods=['GET'])
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

# -------------------------
# Initialization / main
# -------------------------
with app.app_context():
    db.create_all()

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True)
