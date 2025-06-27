from flask_sqlalchemy import SQLAlchemy

user_db = SQLAlchemy()
pwd_db = SQLAlchemy()

class User(user_db.Model):
    __bind_key__ = None  # Default bind (user_data.db)
    id = user_db.Column(user_db.Integer, primary_key=True)
    username = user_db.Column(user_db.String(100), unique=True, nullable=False)
    password = user_db.Column(user_db.String(128), nullable=False)  # Hashed password
    unique_key = user_db.Column(user_db.String(36), unique=True, nullable=False)

    def __repr__(self):
        return f'<User {self.username}>'

    # Flask-Login required methods
    @property
    def is_authenticated(self):
        return True

    @property
    def is_active(self):
        return True

    @property
    def is_anonymous(self):
        return False

    def get_id(self):
        return str(self.id)

class PasswordEntry(pwd_db.Model):
    __bind_key__ = 'passwords'  # Bind to password_data.db
    id = pwd_db.Column(pwd_db.Integer, primary_key=True)
    user_id = pwd_db.Column(pwd_db.Integer, nullable=False)
    purpose = pwd_db.Column(pwd_db.String(100), nullable=False)
    entry_username = pwd_db.Column(pwd_db.String(100), nullable=False)
    data = pwd_db.Column(pwd_db.Text, nullable=False)
    __table_args__ = (pwd_db.UniqueConstraint('user_id', 'entry_username', 'purpose', name='uq_user_entry_purpose'),)