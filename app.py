"""
Streamlined Flask Insurance Management System
Features: User/Agent/Admin auth, KYC, Claims, Policy management, Email reminders
"""
from flask import Flask, render_template, redirect, url_for, flash, session, request, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, TextAreaField, SelectField
from wtforms.validators import DataRequired, Length, Regexp
from flask_mail import Mail, Message
from datetime import datetime, timedelta
import os, random, string
from functools import wraps
from threading import Thread
import time

try:
    from dotenv import load_dotenv
    load_dotenv()
except: pass

# Config
app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.getenv('FLASK_SECRET_KEY', 'dev-secret-key'),
    SQLALCHEMY_DATABASE_URI=f"sqlite:///{os.path.join(os.path.abspath(os.path.dirname(__file__)), 'instance', 'insurance.db')}",
    SQLALCHEMY_TRACK_MODIFICATIONS=False,
    UPLOAD_FOLDER=os.path.join(os.path.abspath(os.path.dirname(__file__)), 'uploads'),
    MAIL_SERVER='smtp.gmail.com', MAIL_PORT=587, MAIL_USE_TLS=True,
    MAIL_USERNAME=os.getenv('MAIL_USERNAME'), MAIL_PASSWORD=os.getenv('MAIL_PASSWORD'),
    MAIL_DEFAULT_SENDER=os.getenv('MAIL_USERNAME')
)
os.makedirs(os.path.dirname(app.config['SQLALCHEMY_DATABASE_URI'].replace('sqlite:///', '')), exist_ok=True)
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

db = SQLAlchemy(app)
mail = Mail(app)

REMINDER_DAYS = [30, 15, 7, 1]
POLICY_VALIDITY_DAYS = 365
CHECK_INTERVAL_HOURS = 24

# Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    kyc_status = db.Column(db.String(20), default='NotSubmitted')
    aadhar = db.Column(db.String(32))
    pan = db.Column(db.String(32))
    kyc_doc = db.Column(db.String(200))
    active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Agent(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    company = db.Column(db.String(120), nullable=False)
    code = db.Column(db.String(20), unique=True, nullable=False)

class Admin(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)

class Policy(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    description = db.Column(db.Text, nullable=False)
    premium = db.Column(db.Float, nullable=False)
    premium_amount = db.Column(db.Float, nullable=False)
    coverage = db.Column(db.Float, nullable=False)
    coverage_amount = db.Column(db.Float, nullable=False)
    
    def __init__(self, name, description, premium, coverage):
        self.name = name
        self.description = description
        self.premium = premium
        self.premium_amount = premium
        self.coverage = coverage
        self.coverage_amount = coverage

class Claim(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ref = db.Column(db.String(30), unique=True, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    policy_type = db.Column(db.String(100), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    description = db.Column(db.Text, nullable=False)
    doc_path = db.Column(db.String(200))
    status = db.Column(db.String(20), default='Pending')
    reviewed_by = db.Column(db.Integer, db.ForeignKey('agent.id'))
    review_notes = db.Column(db.Text)
    submitted_at = db.Column(db.DateTime, default=datetime.utcnow)
    user = db.relationship('User', backref='claims')

class UserPolicy(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    policy_id = db.Column(db.Integer, db.ForeignKey('policy.id'), nullable=False)
    purchase_date = db.Column(db.DateTime, default=datetime.utcnow)
    expiry_date = db.Column(db.DateTime, nullable=False)
    policy = db.relationship('Policy')
    user = db.relationship('User', backref='purchases')

class ReminderLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_policy_id = db.Column(db.Integer, db.ForeignKey('user_policy.id'), nullable=False)
    reminder_days = db.Column(db.Integer, nullable=False)
    sent_at = db.Column(db.DateTime, default=datetime.utcnow)
    user_policy = db.relationship('UserPolicy', backref='reminders')

class AuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    role = db.Column(db.String(20))
    actor_id = db.Column(db.Integer)
    action = db.Column(db.String(400))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

# Forms
class SimpleForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])

class RegForm(FlaskForm):
    email = StringField('Email', validators=[
        DataRequired(),
        Regexp(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', 
               message='Invalid email address')
    ])
    username = StringField('Username', validators=[DataRequired(), Length(4, 80)])
    password = PasswordField('Password', validators=[DataRequired(), Length(6)])

class AgentRegForm(RegForm):
    company_name = StringField('Company', validators=[DataRequired()])
    agent_code = StringField('Agent Code', validators=[DataRequired(), Length(5, 20)])

class ClaimForm(FlaskForm):
    policy_type = SelectField('Policy', validators=[DataRequired()])
    amount = StringField('Amount', validators=[DataRequired()])
    description = TextAreaField('Description', validators=[DataRequired(), Length(10)])

class KYCForm(FlaskForm):
    aadhar = StringField('Aadhar', validators=[DataRequired(), Length(4, 32)])
    pan = StringField('PAN', validators=[DataRequired(), Length(4, 32)])

class PolicyForm(FlaskForm):
    name = StringField('Policy Name', validators=[DataRequired(), Length(3, 100)])
    description = TextAreaField('Description', validators=[DataRequired(), Length(10)])
    premium = StringField('Premium Amount', validators=[DataRequired()])
    coverage = StringField('Coverage Amount', validators=[DataRequired()])

# Helpers
def gen_ref(): return f"CLM-{datetime.utcnow():%Y%m%d}-{''.join(random.choices(string.ascii_uppercase+string.digits, k=6))}"
def gen_otp(n=6): return ''.join(random.choices(string.digits, k=n))
def log(role, aid, action): db.session.add(AuditLog(role=role, actor_id=aid, action=action)); db.session.commit()

def login_required(f):
    @wraps(f)
    def decorated(*a, **k):
        if 'user_id' not in session: flash('Login required', 'warning'); return redirect(url_for('login'))
        u = User.query.get(session['user_id'])
        if not u or not u.active: flash('Account suspended', 'danger'); session.clear(); return redirect(url_for('login'))
        return f(*a, **k)
    return decorated

def agent_required(f):
    @wraps(f)
    def decorated(*a, **k):
        if 'agent_id' not in session: return redirect(url_for('agent_login'))
        return f(*a, **k)
    return decorated

def admin_required(f):
    @wraps(f)
    def decorated(*a, **k):
        if 'admin_id' not in session: return redirect(url_for('admin_login'))
        return f(*a, **k)
    return decorated

# Email Reminders
def send_reminder(email, username, policy_name, days, expiry):
    try:
        urgency = "URGENT: expires tomorrow!" if days == 1 else f"expires in {days} days"
        msg = Message(f"Policy Renewal - {policy_name}", recipients=[email])
        msg.body = f"Dear {username},\n\n{urgency}\n\nPolicy: {policy_name}\nExpiry: {expiry:%B %d, %Y}\nDays Left: {days}\n\nRenew now!\n\nInsurance Team"
        mail.send(msg)
        return True
    except Exception as e: print(f"Email fail: {e}"); return False

def send_purchase_confirmation(email, username, policy_name, premium, expiry):
    try:
        msg = Message(f"Policy Purchase Confirmation - {policy_name}", recipients=[email])
        msg.body = f"""Dear {username},

Congratulations! Your policy has been purchased successfully.

Policy Details:
- Policy Name: {policy_name}
- Premium Amount: ₹{premium:,.2f}
- Purchase Date: {datetime.utcnow():%B %d, %Y}
- Expiry Date: {expiry:%B %d, %Y}
- Validity: 365 days

You will receive renewal reminders at 30, 15, 7, and 1 day before expiry.

Thank you for choosing our insurance services!

Best regards,
Insurance Team"""
        mail.send(msg)
        return True
    except Exception as e: print(f"Email fail: {e}"); return False

def check_reminders():
    with app.app_context():
        try:
            now = datetime.utcnow()
            print(f"\n[{now}] Checking reminders...")
            sent = 0
            for up in UserPolicy.query.all():
                u = User.query.get(up.user_id)
                if not u or not u.active: continue
                days = (up.expiry_date - now).days
                for rd in REMINDER_DAYS:
                    if 0 <= days <= rd and not ReminderLog.query.filter_by(user_policy_id=up.id, reminder_days=rd).first():
                        if send_reminder(u.email, u.username, up.policy.name, days, up.expiry_date):
                            db.session.add(ReminderLog(user_policy_id=up.id, reminder_days=rd))
                            db.session.commit()
                            sent += 1
                            print(f"  ✓ {rd}-day reminder to {u.email}")
            print(f"Sent {sent} reminders\n")
        except Exception as e: print(f"Error: {e}")

def reminder_scheduler():
    while True:
        try: check_reminders(); time.sleep(CHECK_INTERVAL_HOURS * 3600)
        except: time.sleep(3600)

# Routes
@app.route('/')
def index():
    if 'user_id' in session: return redirect(url_for('dashboard'))
    if 'agent_id' in session: return redirect(url_for('agent_dashboard'))
    if 'admin_id' in session: return redirect(url_for('admin_dashboard'))
    return redirect(url_for('login'))

# USER ROUTES
@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegForm()
    if form.validate_on_submit():
        if User.query.filter((User.email == form.email.data) | (User.username == form.username.data)).first():
            flash('User exists', 'danger')
        else:
            session['pending_reg'] = {'email': form.email.data, 'username': form.username.data, 'password': form.password.data}
            otp = gen_otp()
            session['reg_otp'] = otp
            session['reg_otp_exp'] = (datetime.utcnow() + timedelta(minutes=10)).isoformat()
            try:
                mail.send(Message("Registration OTP", recipients=[form.email.data], body=f"OTP: {otp} (10 min)"))
                flash('OTP sent to email', 'info')
                return redirect(url_for('verify_otp'))
            except Exception as e: flash(f'Email error: {e}', 'danger')
    return render_template('register.html', form=form)

@app.route('/verify-otp', methods=['GET', 'POST'])
def verify_otp():
    if request.method == 'POST':
        otp = request.form.get('otp', '').strip()
        pending = session.get('pending_reg')
        saved = session.get('reg_otp')
        exp = session.get('reg_otp_exp')
        if not pending: flash('No pending registration', 'warning'); return redirect(url_for('register'))
        if not saved or (exp and datetime.utcnow() > datetime.fromisoformat(exp)):
            flash('OTP expired', 'danger')
            session.pop('reg_otp', None); session.pop('reg_otp_exp', None); session.pop('pending_reg', None)
            return redirect(url_for('register'))
        if otp == saved:
            u = User(email=pending['email'], username=pending['username'], password=pending['password'])
            db.session.add(u); db.session.commit()
            log('user', u.id, 'Registered')
            session.pop('reg_otp', None); session.pop('reg_otp_exp', None); session.pop('pending_reg', None)
            flash('Registration successful!', 'success')
            return redirect(url_for('login'))
        flash('Invalid OTP', 'danger')
    return render_template('verify_otp.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = SimpleForm()
    if form.validate_on_submit():
        u = User.query.filter_by(username=form.username.data).first()
        if u and u.password == form.password.data:
            if not u.active: flash('Account suspended', 'danger'); return render_template('login.html', form=form)
            session.clear(); session['user_id'] = u.id; session['username'] = u.username
            flash('Logged in!', 'success')
            return redirect(url_for('dashboard'))
        flash('Invalid credentials', 'danger')
    return render_template('login.html', form=form)

@app.route('/logout')
def logout(): session.clear(); flash('Logged out', 'info'); return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    u = User.query.get(session['user_id'])
    claims = Claim.query.filter_by(user_id=u.id).order_by(Claim.submitted_at.desc()).all()
    now = datetime.utcnow()
    expiring = [{'policy': p.policy, 'expiry': p.expiry_date, 'days': (p.expiry_date - now).days} 
                for p in u.purchases if 0 <= (p.expiry_date - now).days <= 30]
    return render_template('dashboard.html', user=u, claims=claims, expiring=expiring)

@app.route('/kyc', methods=['GET', 'POST'])
@app.route('/kyc-upload', methods=['GET', 'POST'])
@login_required
def kyc_upload():
    form = KYCForm()
    u = User.query.get(session['user_id'])
    if form.validate_on_submit():
        f = request.files.get('doc')
        fname = None
        if f and f.filename:
            fname = f"{u.id}_kyc_{int(datetime.utcnow().timestamp())}_{f.filename}"
            f.save(os.path.join(app.config['UPLOAD_FOLDER'], fname))
        u.aadhar = form.aadhar.data; u.pan = form.pan.data; u.kyc_doc = fname; u.kyc_status = 'Pending'
        db.session.commit()
        log('user', u.id, 'KYC submitted')
        flash('KYC submitted', 'info')
        return redirect(url_for('dashboard'))
    return render_template('kyc_upload.html', form=form, user=u)

@app.route('/policies')
@app.route('/browse-policies')
@login_required
def browse_policies():
    return render_template('policies.html', policies=Policy.query.all())

@app.route('/my-policies')
@login_required
def my_policies():
    u = User.query.get(session['user_id'])
    now = datetime.utcnow()
    active = [p for p in u.purchases if p.expiry_date > now]
    expired = [p for p in u.purchases if p.expiry_date <= now]
    return render_template('my_policies.html', active=active, expired=expired)

@app.route('/policies/compare')
@app.route('/compare-policies')
@login_required
def compare_policies():
    return render_template('compare_policies.html', policies=Policy.query.all())

@app.route('/policy/<int:pid>/buy', methods=['GET', 'POST'])
@app.route('/policy/<int:policy_id>/buy', methods=['GET', 'POST'])
@app.route('/policy/<int:pid>/pay', methods=['GET', 'POST'])
@app.route('/policy/<int:policy_id>/pay', methods=['GET', 'POST'])
@login_required
def buy_policy(pid=None, policy_id=None):
    policy_id = pid or policy_id
    u = User.query.get(session['user_id'])
    if u.kyc_status != 'Verified': flash('Complete KYC first', 'warning'); return redirect(url_for('kyc_upload'))
    p = Policy.query.get_or_404(policy_id)
    
    if request.method == 'GET':
        return render_template('payment_checkout.html', policy=p, user=u)
    
    existing = UserPolicy.query.filter_by(user_id=u.id, policy_id=policy_id).first()
    if existing and existing.expiry_date > datetime.utcnow(): 
        flash('Already subscribed', 'info')
        return redirect(url_for('browse_policies'))
    exp = datetime.utcnow() + timedelta(days=POLICY_VALIDITY_DAYS)
    db.session.add(UserPolicy(user_id=u.id, policy_id=policy_id, expiry_date=exp))
    db.session.commit()
    log('user', u.id, f'Bought {p.name}')
    
    # Send purchase confirmation email
    try:
        send_purchase_confirmation(u.email, u.username, p.name, p.premium, exp)
        print(f"Purchase confirmation sent to {u.email}")
    except Exception as e:
        print(f"Failed to send confirmation email: {e}")
    
    return redirect(url_for('payment_success', policy_id=policy_id))

# Add alias for backwards compatibility
pay_policy = buy_policy

@app.route('/payment/success/<int:policy_id>')
@app.route('/payment/success')
@login_required
def payment_success(policy_id=None):
    p = Policy.query.get(policy_id) if policy_id else None
    return render_template('payment_success.html', policy=p)

@app.route('/payment/cancel/<int:policy_id>')
@app.route('/payment/cancel')
@login_required
def payment_cancel(policy_id=None):
    p = Policy.query.get(policy_id) if policy_id else None
    return render_template('payment_cancel.html', policy=p)

@app.route('/claim', methods=['GET', 'POST'])
@app.route('/submit-claim', methods=['GET', 'POST'])
@login_required
def submit_claim():
    form = ClaimForm()
    form.policy_type.choices = [(p.name, p.name) for p in Policy.query.all()]
    u = User.query.get(session['user_id'])
    if u.kyc_status != 'Verified': flash('Complete KYC first', 'warning'); return redirect(url_for('kyc_upload'))
    if form.validate_on_submit():
        try:
            fname = None
            if 'doc' in request.files:
                f = request.files['doc']
                if f and f.filename: fname = f"{gen_ref()}_{f.filename}"; f.save(os.path.join(app.config['UPLOAD_FOLDER'], fname))
            c = Claim(ref=gen_ref(), user_id=u.id, policy_type=form.policy_type.data, amount=float(form.amount.data), 
                     description=form.description.data, doc_path=fname)
            db.session.add(c); db.session.commit()
            log('user', u.id, f'Claim {c.ref}')
            flash(f'Claim submitted: {c.ref}', 'success')
            return redirect(url_for('dashboard'))
        except: flash('Invalid amount', 'danger')
    return render_template('submit_claim.html', form=form)

@app.route('/claim/<ref>')
@app.route('/view-claim/<ref>')
@login_required
def view_claim(ref):
    c = Claim.query.filter_by(ref=ref).first_or_404()
    u = User.query.get(session['user_id'])
    if c.user_id != u.id:
        flash('Unauthorized', 'danger')
        return redirect(url_for('dashboard'))
    return render_template('view_claim.html', claim=c)

# AGENT ROUTES
@app.route('/agent/register', methods=['GET', 'POST'])
def agent_register():
    form = AgentRegForm()
    if form.validate_on_submit():
        if Agent.query.filter((Agent.email == form.email.data) | (Agent.username == form.username.data) | (Agent.code == form.agent_code.data)).first():
            flash('Agent exists', 'danger')
        else:
            a = Agent(email=form.email.data, username=form.username.data, password=form.password.data, company=form.company_name.data, code=form.agent_code.data)
            db.session.add(a); db.session.commit()
            flash('Agent registered', 'success')
            return redirect(url_for('agent_login'))
    return render_template('agent_register.html', form=form)

@app.route('/agent/login', methods=['GET', 'POST'])
def agent_login():
    form = SimpleForm()
    if form.validate_on_submit():
        a = Agent.query.filter_by(username=form.username.data).first()
        if a and a.password == form.password.data:
            session.clear(); session['agent_id'] = a.id
            flash('Logged in!', 'success')
            return redirect(url_for('agent_dashboard'))
        flash('Invalid credentials', 'danger')
    return render_template('agent_login.html', form=form)

@app.route('/agent/logout')
def agent_logout():
    session.clear()
    flash('Logged out', 'info')
    return redirect(url_for('agent_login'))

@app.route('/agent/dashboard')
@agent_required
def agent_dashboard():
    claims = Claim.query.order_by(Claim.submitted_at.desc()).all()
    return render_template('agent_dashboard.html', claims=claims)

@app.route('/agent/claim/<ref>', methods=['GET', 'POST'])
@app.route('/agent/review-claim/<ref>', methods=['GET', 'POST'])
@agent_required
def agent_review_claim(ref):
    c = Claim.query.filter_by(ref=ref).first_or_404()
    if request.method == 'POST':
        c.status = request.form['action']
        c.review_notes = request.form.get('notes', '')
        c.reviewed_by = session['agent_id']
        db.session.commit()
        log('agent', session['agent_id'], f'{c.status} {ref}')
        flash(f'Claim {c.status.lower()}', 'success')
        return redirect(url_for('agent_dashboard'))
    return render_template('agent_review_claim.html', claim=c)

@app.route('/agent/policies')
@agent_required
def agent_policies():
    return render_template('agent_policies.html', policies=Policy.query.all())

@app.route('/agent/policy/add', methods=['GET', 'POST'])
@app.route('/agent/add-policy', methods=['GET', 'POST'])
@agent_required
def agent_add_policy():
    form = PolicyForm()
    if form.validate_on_submit():
        if Policy.query.filter_by(name=form.name.data).first():
            flash('Policy already exists', 'danger')
        else:
            try:
                p = Policy(name=form.name.data, description=form.description.data, 
                          premium=float(form.premium.data), coverage=float(form.coverage.data))
                db.session.add(p)
                db.session.commit()
                log('agent', session['agent_id'], f'Added policy {form.name.data}')
                flash('Policy added successfully', 'success')
                return redirect(url_for('agent_policies'))
            except:
                flash('Invalid data', 'danger')
    return render_template('agent_add_policy.html', form=form)

# ADMIN ROUTES
@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    form = SimpleForm()
    if form.validate_on_submit():
        a = Admin.query.filter_by(username=form.username.data).first()
        if a and a.password == form.password.data:
            session.clear(); session['admin_id'] = a.id
            flash('Admin logged in', 'success')
            return redirect(url_for('admin_dashboard'))
        flash('Invalid credentials', 'danger')
    return render_template('admin_login.html', form=form)

@app.route('/admin/logout')
def admin_logout():
    session.clear()
    flash('Logged out', 'info')
    return redirect(url_for('admin_login'))

@app.route('/admin/dashboard')
@admin_required
def admin_dashboard():
    stats = {'users': User.query.count(), 'active': User.query.filter_by(active=True).count(),
             'pending_kyc': User.query.filter_by(kyc_status='Pending').count(), 
             'pending_claims': Claim.query.filter_by(status='Pending').count()}
    return render_template('admin_dashboard.html', **stats)

@app.route('/admin/kyc')
@app.route('/admin/kyc-requests')
@admin_required
def admin_kyc_requests():
    pending_users = User.query.filter_by(kyc_status='Pending').order_by(User.created_at.desc()).all()
    return render_template('admin_kyc_requests.html', users=pending_users)

@app.route('/admin/kyc/<int:uid>/<action>', methods=['POST'])
@admin_required
def admin_kyc_action(uid, action):
    u = User.query.get_or_404(uid)
    u.kyc_status = 'Verified' if action == 'approve' else 'Rejected'
    db.session.commit()
    log('admin', session['admin_id'], f'{action} KYC {u.username}')
    flash(f'KYC {action}d', 'success')
    return redirect(url_for('admin_kyc_requests'))

@app.route('/admin/users')
@admin_required
def admin_users():
    return render_template('admin_users.html', users=User.query.all())

@app.route('/admin/user/<int:uid>/<action>', methods=['POST'])
@admin_required
def admin_user_action(uid, action):
    u = User.query.get_or_404(uid)
    u.active = action == 'activate'
    db.session.commit()
    log('admin', session['admin_id'], f'{action} {u.username}')
    flash(f'User {action}d', 'success')
    return redirect(url_for('admin_users'))

@app.route('/admin/reminders')
@admin_required
def admin_reminders():
    logs = db.session.query(ReminderLog).join(UserPolicy).order_by(ReminderLog.sent_at.desc()).limit(50).all()
    return render_template('admin_reminders.html', logs=logs)

@app.route('/admin/reminders/check', methods=['POST'])
@admin_required
def trigger_reminders():
    check_reminders()
    flash('Reminder check done', 'success')
    return redirect(url_for('admin_reminders'))

@app.route('/admin/audit')
@app.route('/admin/audit-log')
@admin_required
def admin_audit_log():
    logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).limit(100).all()
    return render_template('admin_audit_log.html', logs=logs)

@app.route('/uploads/<filename>')
@login_required
def upload(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

# Init
def init_db():
    with app.app_context():
        db.create_all()
        if not Admin.query.filter_by(username='admin').first():
            db.session.add(Admin(username='admin', password='admin123'))
            db.session.commit()
            print("Admin created: admin/admin123")
        if not Policy.query.first():
            for p in [('Health Plus', 'Comprehensive health coverage', 5000, 500000),
                      ('Life Gold', 'Term life insurance', 3000, 1000000),
                      ('Vehicle', 'Auto protection', 2500, 300000),
                      ('Home', 'Property protection', 4000, 750000)]:
                policy = Policy(name=p[0], description=p[1], premium=p[2], coverage=p[3])
                db.session.add(policy)
            db.session.commit()
            print("Policies created")

if __name__ == '__main__':
    init_db()
    Thread(target=reminder_scheduler, daemon=True).start()
    print("Reminder scheduler started")
    app.run(debug=True, host='0.0.0.0', port=5000)