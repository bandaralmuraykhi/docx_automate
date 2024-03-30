import os
import tempfile
import uuid
from flask import Flask, render_template, request, redirect, jsonify, send_file, abort, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, SelectMultipleField
from wtforms.validators import DataRequired, Length, Email, EqualTo
from werkzeug.security import generate_password_hash, check_password_hash
from docx import Document

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key'
basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'instance', 'database.db')
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)

class FormResponse(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    form_id = db.Column(db.String(100), nullable=False)
    form_name = db.Column(db.String(100), nullable=False)
    form_link = db.Column(db.String(200), nullable=False)
    selected_cells = db.Column(db.String(500), nullable=False)
    unique_filename = db.Column(db.String(100), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref='form_responses')

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

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
    selected_cells = SelectMultipleField('Selected Cells', coerce=str)
    submit = SubmitField('Update')

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
        hashed_password = generate_password_hash(form.password.data, method='pbkdf2:sha256')
        new_user = User(email=form.email.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
        return redirect(url_for('index'))
    return render_template('signup.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and check_password_hash(user.password, form.password.data):
            login_user(user)
            return redirect(url_for('index'))
        else:
            flash('Invalid email or password. Please try again.')
    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

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
    form_id = str(uuid.uuid4())
    form_url = url_for('fill_form', form_id=form_id, _external=True)
    form_name = f"Form {form_id}"
    form_response = FormResponse(form_id=form_id, form_name=form_name, form_link=form_url,
                                 selected_cells=','.join(selected_cells), unique_filename=unique_filename,
                                 user_id=current_user.id)
    db.session.add(form_response)
    db.session.commit()
    return jsonify({'form_url': form_url, 'selected_cells': selected_cells, 'unique_filename': unique_filename,
                    'form_id': form_id, 'form_name': form_name})

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

            return send_file(temp_file.name, as_attachment=True)
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
            selected_cells = form.selected_cells.data
            form_response.selected_cells = ','.join(selected_cells)
            db.session.commit()
            flash('Form updated successfully.', 'success')
            return redirect(url_for('dashboard'))
        else:
            form.selected_cells.choices = [(cell, cell) for cell in form_response.selected_cells.split(',')]
            return render_template('update_form.html', form=form)
    else:
        flash('Form not found.', 'error')
        return redirect(url_for('dashboard'))

# Initialize Database
def init_db():
    db_file_path = os.path.join(basedir, 'instance', 'database.db')
    if not os.path.exists(db_file_path):
        with app.app_context():
            db.create_all()

init_db()

if __name__ == '__main__':
    app.run(debug=True, port=5001)