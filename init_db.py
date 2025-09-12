from app import db, User, app
from werkzeug.security import generate_password_hash

with app.app_context():
    db.create_all()
    # create default admin if not exists
    if not User.query.filter_by(email='admin@city.gov').first():
        admin = User(
            name='Administrator',
            email='admin@city.gov',
            password_hash=generate_password_hash('admin123'),
            role='admin',
            department='Administration'
        )
        db.session.add(admin)
        db.session.commit()
        print('✅ Created default admin: admin@city.gov / admin123')
    else:
        print('ℹ️ Admin user already exists')
    print('✅ DB init done')
