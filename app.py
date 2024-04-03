import os
import tempfile
import uuid
import hashlib
from flask import Flask, render_template, request, redirect, jsonify, send_file, abort, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_mail import Mail, Message
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, SelectMultipleField
from wtforms.validators import DataRequired, Length, Email, EqualTo
from docx import Document
from itsdangerous import URLSafeTimedSerializer as Serializer

app = Flask(__name__)
app.static_folder = ''
# Access the environment variable `export FLASK_SECRET_KEY=your_secret_key_here`
app.config['SECRET_KEY'] = 'FLASK_SECRET_KEY'
# app.config['SECRET_KEY'] = os.environ.get('FLASK_SECRET_KEY')
basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'instance', 'database.db')
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Configuration for Flask-Mail
app.config.from_pyfile('config.cfg')
mail = Mail(app)

UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

def generate_salt():
    # Generate a 16-byte salt
    return os.urandom(16)

def hash_password(password, salt):
    # Hash a password with the provided salt
    pwdhash = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
    return pwdhash

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(256), nullable=False)
    salt = db.Column(db.LargeBinary(16), nullable=False)
    confirmed = db.Column(db.Boolean, default=False)

    def generate_confirmation_token(self, expiration=3600):
        s = Serializer(app.config['SECRET_KEY'])
        return s.dumps({'confirm': self.id})

    def confirm(self, token):
        s = Serializer(app.config['SECRET_KEY'])
        try:
            data = s.loads(token, max_age=3600)
        except:
            return False
        if data.get('confirm') != self.id:
            return False
        self.confirmed = True
        db.session.commit()
        return True

    def generate_reset_token(self, expiration=3600):
        s = Serializer(app.config['SECRET_KEY'])
        return s.dumps({'reset': self.id})

    @staticmethod
    def reset_password(token, new_password):
        s = Serializer(app.config['SECRET_KEY'])
        try:
            data = s.loads(token, max_age=3600)
        except:
            return False
        user = User.query.get(data.get('reset'))
        if user is None:
            return False
        user.password = new_password
        db.session.commit()
        return True
    
    @staticmethod
    def verify_reset_token(token):
        s = Serializer(app.config['SECRET_KEY'])
        try:
            data = s.loads(token)
        except:
            return None
        return User.query.get(data.get('reset'))

class FormResponse(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    form_id = db.Column(db.String(100), nullable=False)
    form_name = db.Column(db.String(100), nullable=False)
    form_link = db.Column(db.String(200), nullable=False)
    selected_cells = db.Column(db.String(500), nullable=False)
    unique_filename = db.Column(db.String(100), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref='form_responses')
    send_email = db.Column(db.Boolean, default=False)
    allow_download = db.Column(db.Boolean, default=True)

class SignupForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Log In')

class UpdateFormForm(FlaskForm):
    form_name = StringField('Form Name', validators=[DataRequired()])
    selected_cells = SelectMultipleField('Selected Cells', coerce=str)
    submit = SubmitField('Update')

class ResetPasswordRequestForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    submit = SubmitField('Request Password Reset')

class ResendConfirmationForm(FlaskForm):
    submit = SubmitField('Resend Confirmation Email')

class ResetPasswordForm(FlaskForm):
    password = PasswordField('New Password', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Reset Password')

@app.route('/')
def index():
    if current_user.is_authenticated:
        return render_template('index.html')
    else:
        return render_template('home.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = SignupForm()
    if form.validate_on_submit():
        existing_user = User.query.filter_by(email=form.email.data).first()
        if existing_user:
            flash('Email address already exists. Please log in.')
            return redirect(url_for('login'))
        
        # Generating salt and hashing the password
        salt = generate_salt()
        hashed_password = hash_password(form.password.data, salt)
        new_user = User(email=form.email.data, password=hashed_password, salt=salt)
        
        db.session.add(new_user)
        db.session.commit()
        token = new_user.generate_confirmation_token()
        send_email(new_user.email, 'Confirm Your Email', 'confirm_email', user=new_user, token=token)
        flash('A confirmation email has been sent to you.', 'info')
        return redirect(url_for('unconfirmed', email=new_user.email))
    
    return render_template('signup.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            # Hashing the provided password with the stored salt
            hashed_password = hash_password(form.password.data, user.salt)
            if hashed_password == user.password:
                if user.confirmed:
                    login_user(user)
                    return redirect(url_for('index'))
                else:
                    flash('Please confirm your email address to access your account.', 'warning')
                    return redirect(url_for('unconfirmed', email=user.email))
        else:
            flash('Invalid email or password. Please try again.')
    
    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/confirm/<token>')
def confirm(token):
    user = User.query.filter_by(confirmed=False).first()
    if user and user.confirm(token):
        flash('Your email has been confirmed.', 'success')
    else:
        flash('The confirmation link is invalid or has expired.', 'error')
    return redirect(url_for('login'))

@app.route('/unconfirmed', methods=['GET', 'POST'])
def unconfirmed():
    email = request.args.get('email')
    user = User.query.filter_by(email=email).first()
    
    if user and user.confirmed:
        return redirect(url_for('index'))
    
    form = ResendConfirmationForm()
    if form.validate_on_submit():
        if user:
            token = user.generate_confirmation_token()
            send_email(user.email, 'Confirm Your Email', 'confirm_email', user=user, token=token)
            flash('A new confirmation email has been sent to you.', 'info')
        else:
            flash('User not found. Please sign up again.', 'error')
        return redirect(url_for('unconfirmed', email=email))
    
    flash('Your email address is not confirmed. Please check your inbox and confirm your email.', 'warning')
    return render_template('unconfirmed.html', form=form)

@app.route('/reset_password_request', methods=['GET', 'POST'])
def reset_password_request():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = ResetPasswordRequestForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            token = user.generate_reset_token()
            send_email_reset(user.email, 'Reset Your Password', 'reset_password', user=user, token=token)
            flash('An email with instructions to reset your password has been sent to you.', 'info')
            return redirect(url_for('login'))
        else:
            flash('No account found with that email address.', 'error')
    return render_template('reset_password_request.html', form=form)

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    user = User.verify_reset_token(token)
    if not user:
        flash('Invalid or expired reset link.', 'error')
        return redirect(url_for('reset_password_request'))

    form = ResetPasswordForm()
    if form.validate_on_submit():
        # Generate a new salt
        salt = generate_salt()
        # Hash the new password with the generated salt
        hashed_password = hash_password(form.password.data, salt)
        # Update the user's password and salt
        user.password = hashed_password
        user.salt = salt
        db.session.commit()
        flash('Your password has been updated.', 'success')
        return redirect(url_for('login'))

    return render_template('reset_password.html', form=form, user=user)

@app.route('/dashboard')
@login_required
def dashboard():
    form_responses = FormResponse.query.filter_by(user_id=current_user.id).all()
    return render_template('dashboard.html', form_responses=form_responses)

def allowed_file(filename):
    allowed_extensions = ['docx']
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in allowed_extensions

@app.route('/upload', methods=['POST'])
@login_required
def upload_file():
    if 'file' not in request.files:
        return redirect(url_for('index'))
    file = request.files['file']
    if file.filename == '':
        return redirect(url_for('index'))
    if file and allowed_file(file.filename):
        if file.content_length > 10 * 1024 * 1024:  # Limit file size to 10MB
            abort(413)  # Request Entity Too Large
        unique_filename = str(uuid.uuid4()) + '.docx'
        file_path = os.path.join(UPLOAD_FOLDER, unique_filename)
        file.save(file_path)
        document = Document(file_path)
        table_data = []
        unique_cells = set()
        for table in document.tables:
            for row in table.rows:
                row_data = []
                for cell in row.cells:
                    cell_text = cell.text.strip()
                    if cell_text not in unique_cells:
                        unique_cells.add(cell_text)
                        row_data.append(cell_text)
                if row_data:
                    table_data.append(row_data)
        return jsonify({'table_data': table_data, 'unique_filename': unique_filename})
    return redirect(url_for('index'))

@app.route('/create_form', methods=['POST'])
@login_required
def create_form():
    selected_cells = request.json.get('selected_cells', [])
    unique_filename = request.json.get('unique_filename', '')
    send_email = request.json.get('send_email', False)
    allow_download = request.json.get('allow_download', True)
    form_id = str(uuid.uuid4())
    form_url = url_for('fill_form', form_id=form_id, _external=True)
    form_name = f"Form {form_id}"
    form_response = FormResponse(
        form_id=form_id,
        form_name=form_name,
        form_link=form_url,
        selected_cells=','.join(selected_cells),
        unique_filename=unique_filename,
        user_id=current_user.id,
        send_email=send_email,
        allow_download=allow_download
    )
    db.session.add(form_response)
    db.session.commit()
    return jsonify({
        'form_url': form_url,
        'selected_cells': selected_cells,
        'unique_filename': unique_filename,
        'form_id': form_id,
        'form_name': form_name
    })

@app.route('/fill_form/<form_id>', methods=['GET', 'POST'])
def fill_form(form_id):
    if request.method == 'POST':
        form_data = request.form
        form_response = FormResponse.query.filter_by(form_id=form_id).first()
        if form_response:
            file_path = os.path.join(UPLOAD_FOLDER, form_response.unique_filename)
            document = Document(file_path)
            for cell_text, value in form_data.items():
                if cell_text != 'unique_filename':
                    for table in document.tables:
                        for row in table.rows:
                            for cell in row.cells:
                                if cell.text.strip() == cell_text:
                                    # Preserve the original formatting and style of the cell
                                    cell_paragraph = cell.paragraphs[0]
                                    original_text = cell_paragraph.text
                                    run = cell_paragraph.add_run(value)
                                    run.font.name = cell_paragraph.runs[0].font.name
                                    run.font.size = cell_paragraph.runs[0].font.size
                                    run.bold = cell_paragraph.runs[0].bold
                                    run.italic = cell_paragraph.runs[0].italic
                                    run.underline = cell_paragraph.runs[0].underline

            temp_file = tempfile.NamedTemporaryFile(delete=False, suffix='.docx')
            document.save(temp_file.name)
            temp_file.close()

            if form_response.send_email:
                user = User.query.get(form_response.user_id)
                if user:
                    msg = Message('Modified File', recipients=[user.email])
                    msg.body = 'Please find the attached modified file.'
                    with open(temp_file.name, 'rb') as f:
                        msg.attach(form_response.form_name + '.docx', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document', f.read())
                    mail.send(msg)

            if form_response.allow_download:
                return send_file(temp_file.name, as_attachment=True)
            else:
                return 'File modification completed, but download is not allowed.'
        else:
            abort(404)
    else:
        form_response = FormResponse.query.filter_by(form_id=form_id).first()
        if form_response:
            selected_cells = form_response.selected_cells.split(',')
            unique_filename = form_response.unique_filename
            return render_template('fill_form.html', form_id=form_id, selected_cells=selected_cells, unique_filename=unique_filename)
        else:
            abort(404)

@app.route('/delete_form/<form_id>', methods=['GET'])
@login_required
def delete_form(form_id):
    form_response = FormResponse.query.filter_by(form_id=form_id, user_id=current_user.id).first()
    if form_response:
        db.session.delete(form_response)
        db.session.commit()
        flash('Form deleted successfully.', 'success')
    else:
        flash('Form not found.', 'error')
    return redirect(url_for('dashboard'))

@app.route('/update_form/<form_id>', methods=['GET', 'POST'])
@login_required
def update_form(form_id):
    form_response = FormResponse.query.filter_by(form_id=form_id, user_id=current_user.id).first()
    if form_response:
        form = UpdateFormForm()
        if request.method == 'POST':
            form_response.form_name = form.form_name.data
            selected_cells = request.form.getlist('selected_cells')  # Get selected cells from the form
            form_response.selected_cells = ','.join(selected_cells)
            db.session.commit()
            flash('Form updated successfully.', 'success')
            return redirect(url_for('dashboard'))
        else:
            # Fetch unique cell values from the current form response
            all_cells = set(form_response.selected_cells.split(','))
            form.selected_cells.choices = [(cell, cell) for cell in all_cells]
            # Preselect cells based on existing data
            form.selected_cells.data = form_response.selected_cells.split(',')
            form.form_name.data = form_response.form_name
            return render_template('update_form.html', form=form)
    else:
        flash('Form not found.', 'error')
        return redirect(url_for('dashboard'))

def send_email(to, subject, template, **kwargs):
    msg = Message(subject, recipients=[to])
    msg.body = render_template(template + '.txt', **kwargs)
    msg.html = render_template(template + '.html', **kwargs)
    mail.send(msg)

def send_email_reset(to, subject, template, **kwargs):
    msg = Message(subject, recipients=[to])
    msg.body = render_template(template + '.txt', **kwargs)
    msg.html = render_template(template + '_email.html', **kwargs)
    mail.send(msg)

with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(debug=True, port=5001)