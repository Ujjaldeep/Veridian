from flask import Flask, render_template, request, redirect, url_for, flash, abort, make_response
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from flask_bcrypt import Bcrypt
from custom.database import user_db, pwd_db, User, PasswordEntry
from custom.encdec import encryptor, decryptor
import logging, re, uuid, pickle, os, secrets

logging.basicConfig(level=logging.DEBUG)

app = Flask(__name__)

databases_dir = os.path.join(os.path.dirname(__file__), 'databases')
os.makedirs(databases_dir, exist_ok=True)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(databases_dir, 'user_data.db')  # User database
app.config['SQLALCHEMY_BINDS'] = {
    'passwords': 'sqlite:///' + os.path.join(databases_dir, 'password_data.db')  # Password entries database
}
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

key_dir = os.path.join(os.getcwd(),"var\\mai-intance\\key.mp3")

try:
    with open(key_dir, "rb") as f:
        app.config['SECRET_KEY'] = pickle.load(f)
except:
    secret_key = secrets.token_hex(16)
    with open(key_dir,"wb") as f:
        pickle.dump(secret_key,f)
    app.config['SECRET_KEY'] = secret_key

user_db.init_app(app)
pwd_db.init_app(app)
bcrypt = Bcrypt(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return user_db.session.get(User, int(user_id))

with app.app_context():
    user_db.create_all()
    pwd_db.create_all(bind='passwords')

# Add cache-control headers for protected routes
@app.after_request
def add_no_cache_headers(response):
    protected_routes = ['/dashboard', '/update', '/delete']
    if request.path in protected_routes:
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
    return response

@app.route('/check-auth')
def check_auth():
    return {'authenticated': current_user.is_authenticated}

@app.errorhandler(404)
def page_not_found(e):
    logging.error(f"404 error: {request.url}")
    return render_template('404.html'), 404

@app.route('/')
def landing():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    return redirect(url_for('welcome'))

@app.route('/welcome')
def welcome():
    return render_template('home.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['email']
        password = request.form['password']

        if not username or not password:
            flash('All fields are required.', 'error')
            return redirect(url_for('signup'))
        if not re.match(r'^[a-zA-Z0-9_@.]+$', username):
            flash('Invalid username: Use only letters, numbers, underscores, @, or .', 'error')
            return redirect(url_for('signup'))
        if len(password) < 6 or ' ' in password or not re.match(r'^[A-Za-z0-9!@#$%_+.\-]+$', password):
            flash('Password must be at least 6 characters, no spaces, and only allowed symbols.', 'error')
            return redirect(url_for('signup'))
        if user_db.session.query(User).filter_by(username=username).first():
            flash('Username already exists.', 'error')
            return redirect(url_for('signup'))

        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        unique_key = str(uuid.uuid4())
        user = User(username=username, password=hashed_password, unique_key=unique_key)
        user_db.session.add(user)
        user_db.session.commit()

        flash(f'Account created! Your unique key is: {unique_key}. Save it securely!', 'success')
        return redirect(url_for('login'))

    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['email']
        password = request.form['password']
        unique_key = request.form['unique_key']

        user = user_db.session.query(User).filter_by(username=username).first()
        if user and bcrypt.check_password_hash(user.password, password) and user.unique_key == unique_key:
            login_user(user)
            flash('Logged in successfully!', 'success')
            return redirect(url_for('home'))
        else:
            flash('Invalid username, password, or unique key.', 'error')
            return redirect(url_for('login'))

    return render_template('login.html')

@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def home():
    if request.method == 'POST':
        purpose = request.form['Purpose'].strip()
        entry_username = request.form['Username'].strip()
        pwd = request.form['Password'].strip()

        if not purpose or not entry_username or not pwd:
            flash("All fields are required", "error")
            return redirect(url_for('home'))
        if not re.match(r'^[a-zA-Z0-9 #\-_\/]+$', purpose):
            flash("Invalid purpose format", "error")
            return redirect(url_for('home'))
        if not re.match(r'^[a-zA-Z0-9_@.]+$', entry_username):
            flash("Invalid username", "error")
            return redirect(url_for('home'))
        if len(pwd) < 6 or ' ' in pwd or not re.match(r'^[A-Za-z0-9!@#$%_+.\-]+$', pwd):
            flash("Invalid password format", "error")
            return redirect(url_for('home'))
        if pwd_db.session.query(PasswordEntry).filter_by(user_id=current_user.id, purpose=purpose, entry_username=entry_username).first():
            flash("Username and purpose combination already exists", "error")
            return redirect(url_for('home'))

        enc_data = encryptor(entry_username, pwd)
        new_entry = PasswordEntry(purpose=purpose, user_id=current_user.id, entry_username=entry_username, data=enc_data)
        try:
            pwd_db.session.add(new_entry)
            pwd_db.session.commit()
            flash("Entry added successfully", "success")
        except Exception as e:
            logging.error(f"Error adding entry: {e}")
            flash(f"Error saving entry: {e}", "error")
        return redirect(url_for('home'))

    entries = pwd_db.session.query(PasswordEntry).filter_by(user_id=current_user.id).all()
    datalist = []
    for e in entries:
        try:
            dec = decryptor(e.data)
            if not re.match(r'^[A-Za-z0-9!@#$%_+.\-]+$', dec[1]):
                datalist.append([e.purpose, e.entry_username, "Invalid password"])
            else:
                datalist.append([e.purpose, e.entry_username, dec[1]])
        except Exception as e:
            logging.error(f"Decryption error: {e}")
            datalist.append([e.purpose, e.entry_username, "Decryption failed"])
    response = make_response(render_template('index.html', datalist=datalist))
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response

@app.route('/delete/<string:entry_username>/<string:purpose>')
@login_required
def delete(entry_username, purpose):
    if not entry_username or not purpose:
        abort(404)
    del_cred = pwd_db.session.query(PasswordEntry).filter_by(user_id=current_user.id, entry_username=entry_username, purpose=purpose).first_or_404()
    try:
        pwd_db.session.delete(del_cred)
        pwd_db.session.commit()
        flash(f"Deleted entry for {entry_username} ({purpose})", "success")
    except Exception as e:
        logging.error(f"Delete error: {e}")
        flash(f"Error deleting entry: {e}", "error")
    return redirect(url_for('home'))

@app.route('/update/<string:entry_username>/<string:purpose>', methods=['GET', 'POST'])
@login_required
def update(entry_username, purpose):
    entry = pwd_db.session.query(PasswordEntry).filter_by(user_id=current_user.id, entry_username=entry_username, purpose=purpose).first_or_404()
    if request.method == 'POST':
        new_purpose = request.form['Purpose'].strip()
        new_entry_username = request.form['Username'].strip()
        pwd = request.form['Password'].strip()

        if not new_purpose: new_purpose = purpose
        if not new_entry_username: new_entry_username = entry_username
        if not pwd:
            flash("All fields are required", "error")
            return render_template('update.html', entry=entry)
        if not re.match(r'^[a-zA-Z0-9 #\-_\/]+$', new_purpose):
            flash("Invalid purpose format", "error")
            return render_template('update.html', entry=entry)
        if not re.match(r'^[a-zA-Z0-9_@.]+$', new_entry_username):
            flash("Invalid username", "error")
            return render_template('update.html', entry=entry)
        if len(pwd) < 6 or ' ' in pwd or not re.match(r'^[A-Za-z0-9!@#$%_+.\-]+$', pwd):
            flash("Invalid password format", "error")
            return render_template('update.html', entry=entry)
        if (new_entry_username != entry_username or new_purpose != purpose) and pwd_db.session.query(PasswordEntry).filter_by(user_id=current_user.id, entry_username=new_entry_username, purpose=new_purpose).first():
            flash("Username and purpose combination already exists", "error")
            return render_template('update.html', entry=entry)

        try:
            if new_entry_username != entry_username or new_purpose != purpose:
                pwd_db.session.delete(entry)
                enc_data = encryptor(new_entry_username, pwd)
                new_entry = PasswordEntry(purpose=new_purpose, user_id=current_user.id, entry_username=new_entry_username, data=enc_data)
                pwd_db.session.add(new_entry)
            else:
                entry.purpose = new_purpose
                entry.data = encryptor(new_entry_username, pwd)
            pwd_db.session.commit()
            flash("Entry updated successfully", "success")
            return redirect(url_for('home'))
        except Exception as e:
            logging.error(f"Update error: {e}")
            flash(f"Error updating entry: {e}", "error")
            return render_template('update.html', entry=entry)
    response = make_response(render_template('update.html', entry=entry))
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out successfully!', 'success')
    response = make_response(redirect(url_for('welcome')))
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response

if __name__ == '__main__':
    with app.app_context():
        user_db.create_all()
        pwd_db.create_all(bind='passwords')
    app.run(debug=True)
