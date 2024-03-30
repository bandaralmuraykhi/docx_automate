import os
import tempfile
import uuid
from flask import Flask, render_template, request, redirect, jsonify, send_file, abort, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Length, Email, EqualTo
from docx import Document

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
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
    data = db.Column(db.JSON, nullable=False)
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

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = SignupForm()
    if form.validate_on_submit():
        existing_user = User.query.filter_by(email=form.email.data).first()
        if existing_user:
            flash('Email address already exists. Please log in.')
            return redirect(url_for('login'))
        new_user = User(email=form.email.data, password=form.password.data)
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
        return redirect(url_for('dashboard'))
    return render_template('signup.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and user.password == form.password.data:
            login_user(user)
            return redirect(url_for('dashboard'))
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
def upload_file():
    if 'file' not in request.files:
        return redirect('/')
    file = request.files['file']
    if file.filename == '':
        return redirect('/')
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
    return redirect('/')

@app.route('/create_form', methods=['POST'])
def create_form():
    selected_cells = request.json.get('selected_cells', [])
    unique_filename = request.json.get('unique_filename', '')
    form_id = str(uuid.uuid4())
    form_url = url_for('fill_form', form_id=form_id, _external=True)
    return jsonify({'form_url': form_url, 'selected_cells': selected_cells, 'unique_filename': unique_filename})

@app.route('/fill_form/<form_id>', methods=['GET', 'POST'])
def fill_form(form_id):
    if request.method == 'POST':
        form_data = request.form
        unique_filename = form_data.get('unique_filename')
        file_path = os.path.join(UPLOAD_FOLDER, unique_filename)
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

        # Save the form response
        form_response = FormResponse(form_id=form_id, data=form_data, user_id=current_user.id)
        db.session.add(form_response)
        db.session.commit()

        temp_file = tempfile.NamedTemporaryFile(delete=False, suffix='.docx')
        document.save(temp_file.name)
        temp_file.close()

        return send_file(temp_file.name, as_attachment=True)
    else:
        selected_cells = request.args.get('selected_cells', '').split(',')
        unique_filename = request.args.get('unique_filename', '')
        return render_template('fill_form.html', form_id=form_id, selected_cells=selected_cells, unique_filename=unique_filename)

if __name__ == '__main__':
    app.run(debug=True, port=5001)