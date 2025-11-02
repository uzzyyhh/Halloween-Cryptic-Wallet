# app.py  (Flask >= 2.3 compatible)
import os
import secrets
from datetime import timedelta, datetime
from flask import Flask, render_template, request, redirect, url_for, session, flash, g, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from database import (
    init_db, get_user, add_user, log_action, get_logs, get_user_by_username,
    update_profile, add_transaction, get_transactions, reset_failed_attempts,
    increment_failed_attempts
)
from security import is_strong_password, encrypt_data, decrypt_data, sanitize_input, get_or_create_key
from functools import wraps

# Configuration
UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
MAX_CONTENT_BYTES = 16 * 1024 * 1024   # 16 MB

# App init
app = Flask(__name__, static_folder='static', template_folder='templates')
# Secret key from env or fallback (for production use env)
app.secret_key = os.environ.get('FLASK_SECRET_KEY') or secrets.token_urlsafe(32)
app.permanent_session_lifetime = timedelta(minutes=5)  # session expires after 5 minutes of inactivity
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_BYTES'] = MAX_CONTENT_BYTES
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Ensure encryption key exists (security module manages file/env)
FERNET_KEY = get_or_create_key()

# Initialize database
with app.app_context():
    init_db()

# Helpers
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.before_request
def load_logged_in_user():
    user_id = session.get('user_id')
    if user_id:
        user = get_user(user_id)
        if user:
            g.user = user
        else:
            session.clear()
            g.user = None
    else:
        g.user = None

# ============================
# Enhanced login_required()
# ============================
def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        user_id = session.get('user_id')
        login_time = session.get('login_at')

        # If user not logged in or session missing
        if not user_id or not login_time:
            flash('Your session has expired due to inactivity. Please log in again.', 'error')
            session.clear()
            return redirect(url_for('login'))

        # Check if session lifetime exceeded
        try:
            last_login = datetime.fromisoformat(login_time)
            if datetime.utcnow() - last_login > app.permanent_session_lifetime:
                flash('Your session has expired due to inactivity. Please log in again.', 'error')
                session.clear()
                return redirect(url_for('login'))
        except Exception:
            session.clear()
            flash('Session error occurred. Please log in again.', 'error')
            return redirect(url_for('login'))

        # Refresh session time for continued activity
        session['login_at'] = datetime.utcnow().isoformat()
        g.user = get_user(user_id)
        return view(*args, **kwargs)
    return wrapped

# Routes
@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    # guarantee fresh session on first GET to reduce session fixation risk
    if request.method == 'GET':
        if '_flashes' not in session:
            session.clear()
    if request.method == 'POST':
        username = sanitize_input(request.form.get('username', '')).strip()
        password = request.form.get('password', '')

        if not username or not password:
            flash('All fields required!', 'error')
            return render_template('login.html')

        user = get_user_by_username(username)
        # if account is locked (5 or more failed)
        if user and user['failed_attempts'] >= 5:
            flash('Account locked after too many failed attempts. Contact admin.', 'error')
            log_action(user['id'], 'login_locked', f'Locked login attempt for {username}')
            return render_template('login.html')

        if user and check_password_hash(user['password_hash'], password):
            # Successful login - reset session and set user_id
            session.clear()
            session.permanent = True
            session['user_id'] = int(user['id'])
            session['login_at'] = datetime.utcnow().isoformat()
            log_action(int(user['id']), 'login', 'Success')
            reset_failed_attempts(username)
            flash('Welcome back to the crypt!', 'success')
            return redirect(url_for('dashboard'))
        else:
            increment_failed_attempts(username)
            flash('Invalid credentials.', 'error')
            uid = user['id'] if user else None
            log_action(uid, 'login_failed', f'Failed: {username}')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = sanitize_input(request.form.get('username', '')).strip()
        password = request.form.get('password', '')
        confirm = request.form.get('confirm_password', '')
        email = sanitize_input(request.form.get('email', '')).strip()

        if not username or not password or not email or not confirm:
            flash('All fields required!', 'error')
            return render_template('register.html')

        if get_user_by_username(username):
            flash('Username already exists!', 'error')
            return render_template('register.html')

        if password != confirm:
            flash('Passwords do not match!', 'error')
            return render_template('register.html')

        if not is_strong_password(password):
            flash('Password must be at least 8 chars and include uppercase, lowercase, digit, and symbol!', 'error')
            return render_template('register.html')

        if '@' not in email or '.' not in email.split('@')[-1]:
            flash('Invalid email!', 'error')
            return render_template('register.html')

        hashed = generate_password_hash(password)
        user_id = add_user(username, hashed, email)
        log_action(user_id, 'register', f'New user: {username}')
        flash('Registration successful! Please login.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/dashboard')
@login_required
def dashboard():
    transactions = get_transactions(session['user_id'])
    return render_template('dashboard.html', user=g.user, transactions=transactions)

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    if request.method == 'POST':
        email = sanitize_input(request.form.get('email', '')).strip()
        if not email or '@' not in email or '.' not in email.split('@')[-1]:
            flash('Invalid email!', 'error')
        else:
            update_profile(session['user_id'], email)
            flash('Profile updated successfully!', 'success')
            log_action(session['user_id'], 'profile_update', 'Email changed')
            g.user = get_user(session['user_id'])
    return render_template('profile.html', user=g.user)

@app.route('/transfer', methods=['GET', 'POST'])
@login_required
def transfer():
    if request.method == 'POST':
        recipient = sanitize_input(request.form.get('recipient', '')).strip()
        amount_str = request.form.get('amount', '').strip()
        note = request.form.get('note', '').strip()

        if not recipient or not amount_str or not note:
            flash('All fields required!', 'error')
            return render_template('transfer.html')

        try:
            amount = float(amount_str)
            if amount <= 0:
                raise ValueError
        except ValueError:
            flash('Invalid amount!', 'error')
            return render_template('transfer.html')

        encrypted_note = encrypt_data(note.encode()).hex()
        add_transaction(session['user_id'], recipient, amount, encrypted_note)
        log_action(session['user_id'], 'transfer', f'Sent ${amount:.2f} to {recipient}')
        flash('Transfer successful!', 'success')
        return redirect(url_for('dashboard'))
    return render_template('transfer.html')

@app.route('/upload', methods=['POST'])
@login_required
def upload():
    if 'file' not in request.files:
        flash('No file uploaded!', 'error')
        return redirect(url_for('profile'))
    file = request.files['file']
    if not file or file.filename == '':
        flash('No file selected!', 'error')
        return redirect(url_for('profile'))

    if not allowed_file(file.filename):
        flash('Invalid file type!', 'error')
        return redirect(url_for('profile'))

    file.stream.seek(0, os.SEEK_END)
    size = file.stream.tell()
    file.stream.seek(0)
    if size > app.config['MAX_CONTENT_BYTES']:
        flash('File too large!', 'error')
        return redirect(url_for('profile'))

    ext = secure_filename(file.filename).rsplit('.', 1)[1].lower()
    unique_name = f"{secrets.token_hex(16)}.{ext}"
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], unique_name)
    file.save(filepath)
    log_action(session['user_id'], 'file_upload', f'Uploaded {unique_name}')
    flash('File uploaded securely!', 'success')
    return redirect(url_for('profile'))

@app.route('/uploads/<path:filename>')
@login_required
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename, as_attachment=False)

@app.route('/logs')
@login_required
def logs():
    user_logs = get_logs(session['user_id'])
    return render_template('logs.html', logs=user_logs)

@app.route('/logout')
def logout():
    if session.get('user_id'):
        try:
            log_action(int(session['user_id']), 'logout', 'Logged out')
        except Exception:
            pass
    session.clear()
    flash('Logged out safely!', 'success')
    return redirect(url_for('login'))

@app.route('/test/error')
def test_error():
    raise RuntimeError("Deliberate test error")

@app.template_filter('hex_to_note')
def _hex_to_note(h):
    try:
        if not h:
            return ''
        return decrypt_data(bytes.fromhex(h)).decode()
    except Exception:
        return ''

@app.errorhandler(404)
def not_found(e):
    return render_template('base.html', content="<h2>404 - Page Not Found</h2><p>Even ghosts can't find this page!</p>"), 404

@app.errorhandler(500)
def internal_error(e):
    return render_template('error.html'), 500

if __name__ == '__main__':
    debug_mode = os.environ.get('FLASK_DEBUG', '0') == '1'
    app.run(debug=debug_mode, host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))
