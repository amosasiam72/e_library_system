from flask import Flask, render_template, redirect, url_for, request, flash
from flask_wtf import FlaskForm
from wtforms import SelectField, StringField, PasswordField, SubmitField, TextAreaField
from wtforms.validators import DataRequired, Email, Optional
from flask_login import LoginManager, login_user, logout_user, login_required, current_user, UserMixin
import os
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, login_required, current_user
from flask_wtf.file import FileField, FileAllowed
from datetime import datetime



# Initializing Flask application and configuring it
app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret-key-here'  # we will change this later to something secure
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///library.db'
app.config['UPLOAD_FOLDER'] = 'static/uploads'


db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login' 

LEVEL_CHOICES = [
    ('100', 'Level 100'),
    ('200', 'Level 200'),
    ('300', 'Level 300'),
    ('400', 'Level 400'),
]

PROGRAM_CHOICES = [
    ('Select', 'Select'),
    ('Information Technology', 'Information Technology'),
    ('Computer Science', 'Computer Science'),
    ('Information Systems', 'Information Systems'),
    ('Mobile Computing', 'Mobile Computing'),
    ('Engineering', 'Engineering'),
    ('Cyber Security', 'Cyber Security'),
    ('Software Engineering', 'Software Engineering'),
    ('Data and Analytics', 'Data and Analytics'),
]


# Database models for User, Book, AccessLog, and Recommendation
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), default='student')
    program = db.Column(db.String(100), nullable=True)
    level = db.Column(db.String(10), nullable=True)   

class Book(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    author = db.Column(db.String(100), nullable=False)
    program = db.Column(db.String(100), nullable=False)
    level = db.Column(db.String(10), nullable=False)
    filename = db.Column(db.String(100), nullable=False)
    keywords = db.Column(db.String(200), nullable=True)


class AccessLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    book_id = db.Column(db.Integer, db.ForeignKey('book.id'))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship('User', backref='access_logs')
    book = db.relationship('Book', backref='access_logs')   

class Recommendation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), nullable=False)
    title = db.Column(db.String(200), nullable=False)
    author = db.Column(db.String(100), nullable=False)
    program = db.Column(db.String(100), nullable=False)
    level = db.Column(db.String(10), nullable=False)
    keywords = db.Column(db.String(200), nullable=True)
    message = db.Column(db.Text, nullable=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)




@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))



# Create database file automatically if it doesn't exist
if not os.path.exists('library.db'):
    with app.app_context():
        db.create_all()

# Forms for registration, login, book upload, and other functionalities
class RegisterForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    program = SelectField('Program of Study', choices=PROGRAM_CHOICES, validators=[DataRequired()])
    level = SelectField('Academic Level', choices=LEVEL_CHOICES, validators=[DataRequired()])
    submit = SubmitField('Register')


class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class BookForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired()])
    author = StringField('Author', validators=[DataRequired()])
    program = SelectField('Program of Study', choices=PROGRAM_CHOICES, validators=[DataRequired()])
    level = SelectField('Academic Level', choices=LEVEL_CHOICES, validators=[DataRequired()])
    file = FileField('Upload Book (PDF only)', validators=[DataRequired(), FileAllowed(['pdf'], 'PDF only!')])
    keywords = StringField('Keywords (comma-separated)', validators=[DataRequired()])
    submit = SubmitField('Upload Book')

class UpdateLevelForm(FlaskForm):
    level = SelectField('Academic Level', choices=LEVEL_CHOICES, validators=[DataRequired()])
    submit = SubmitField('Update Level')

class EditBookForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired()])
    author = StringField('Author', validators=[DataRequired()])
    program = SelectField('Program of Study', choices=PROGRAM_CHOICES, validators=[DataRequired()])
    level = SelectField('Academic Level', choices=LEVEL_CHOICES, validators=[DataRequired()])
    keywords = StringField('Keywords (comma-separated)', validators=[DataRequired()])
    submit = SubmitField('Update Book')

class RecommendForm(FlaskForm):
    name = StringField('Your Name', validators=[DataRequired()])
    email = StringField('Your Email', validators=[DataRequired(), Email()])
    title = StringField('Book Title', validators=[DataRequired()])
    author = StringField('Author', validators=[DataRequired()])
    program = SelectField('Program of Study', choices=PROGRAM_CHOICES, validators=[DataRequired()])
    level = SelectField('Academic Level', choices=LEVEL_CHOICES, validators=[DataRequired()])
    keywords = StringField('Keywords (comma-separated)', validators=[DataRequired()])
    message = TextAreaField('Optional Message')
    submit = SubmitField('Submit Recommendation')

class AddUserForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    program = SelectField('Program (for students/lecturers)',choices=PROGRAM_CHOICES, validators=[Optional()])
    level = SelectField('Level (for students/lecturers)', choices=LEVEL_CHOICES, validators=[Optional()])
    role = SelectField('Role', choices=[('student', 'Student'), ('lecturer', 'Lecturer'), ('admin', 'Admin')], validators=[DataRequired()])
    submit = SubmitField('Add User')






# Route definitions for the application
@app.route('/')
def home():
    return render_template('index.html')

# Code for user registration(students only)
@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        hashed_pw = generate_password_hash(form.password.data)
        user = User(
            name=form.name.data,
            email=form.email.data,
            password=hashed_pw,
            program=form.program.data,
            level=form.level.data,
            role='student'  
        )
        db.session.add(user)
        db.session.commit()
        flash("Registration successful. You can now log in.", "success")
        return redirect(url_for('login'))  
    return render_template('register.html', form=form)

# Code for user login (students, lecturers, and admin)
@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and check_password_hash(user.password, form.password.data):
            login_user(user)
            flash("Login successful!", "success")
            return redirect(url_for('dashboard'))

        else:
           flash("Invalid email or password.", "danger")
    return render_template('login.html', form=form)

# Code for the dashboard, which redirects based on user role
@app.route('/dashboard')
@login_required
def dashboard():
    if current_user.role == 'admin':
        return render_template('admin_dashboard.html', user=current_user)
    elif current_user.role == 'student':
        return render_template('student_dashboard.html', user=current_user)
    elif current_user.role == 'lecturer':
        return redirect(url_for('lecturer_dashboard'))
    else:
        return "Unknown role"

# Code for uploading books (admin only)
@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload():
    if current_user.role != 'admin':
        return "Access denied. Only admins can upload books."

    form = BookForm()
    if form.validate_on_submit():
        file = form.file.data
        filename = file.filename
        save_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(save_path)

        new_book = Book(
            title=form.title.data,
            author=form.author.data,
            program=form.program.data,
            level=form.level.data,
            keywords=form.keywords.data,
            filename=filename
        )
        db.session.add(new_book)
        db.session.commit()
        return "Book uploaded successfully!"
    return render_template('upload.html', form=form)

#Code for searching and filtering books to be recommended to students 
@app.route('/books', methods=['GET', 'POST'])
@login_required
def books():
    search_query = request.args.get('q', '')
    program = request.args.get('program', current_user.program)
    level = request.args.get('level', current_user.level)

    query = Book.query.filter_by(program=program, level=level)

    books = query.all()

    return render_template('books.html', books=books, search=search_query, program=program, level=level)

#Code for reading books
@app.route('/read/<int:book_id>')
@login_required
def read_book(book_id):
    book = Book.query.get_or_404(book_id)

    # Log student access
    if current_user.role == 'student':
        log = AccessLog(user_id=current_user.id, book_id=book.id)
        db.session.add(log)
        db.session.commit()

    return render_template('read_book.html', book=book)

# Code for viewing access history
@app.route('/history')
@login_required
def history():
    if current_user.role != 'student':
        return "Access denied."

    logs = AccessLog.query.filter_by(user_id=current_user.id).order_by(AccessLog.timestamp.desc()).all()
    return render_template('history.html', logs=logs)

# Code for viewing library of books
@app.route('/library')
@login_required
def library():
    page = request.args.get('page', 1, type=int)
    search_query = request.args.get('q', '')
    query = Book.query

    if search_query:
        query = query.filter(
            (Book.title.ilike(f'%{search_query}%')) |
            (Book.author.ilike(f'%{search_query}%')) |
            (Book.keywords.ilike(f'%{search_query}%'))
        )

    books = query.order_by(Book.title).paginate(page=page, per_page=10)
    return render_template('library.html', books=books, search=search_query)


# Code for updating academic level
@app.route('/update-level', methods=['GET', 'POST'])
@login_required
def update_level():
    if current_user.role != 'student':
        return "Access denied."

    form = UpdateLevelForm()
    if form.validate_on_submit():
        current_user.level = form.level.data
        db.session.commit()
        flash("Academic level updated successfully!", "success")
        return redirect(url_for('dashboard'))

    return render_template('update_level.html', form=form)

# Code for managing books (admin only)
@app.route('/manage-books')
@login_required
def manage_books():
    if current_user.role != 'admin':
        return "Access denied."

    books = Book.query.order_by(Book.title).all()
    return render_template('manage_books.html', books=books)

# Code for editing a book (admin only)
@app.route('/edit-book/<int:book_id>', methods=['GET', 'POST'])
@login_required
def edit_book(book_id):
    if current_user.role != 'admin':
        return "Access denied."

    book = Book.query.get_or_404(book_id)
    form = EditBookForm(obj=book)

    if form.validate_on_submit():
        book.title = form.title.data
        book.author = form.author.data
        book.program = form.program.data
        book.level = form.level.data
        book.keywords = form.keywords.data
        db.session.commit()
        flash("Book updated successfully.", "success")
        return redirect(url_for('manage_books'))

    return render_template('edit_book.html', form=form, book=book)

# Code for deleting a book (admin only)
@app.route('/delete-book/<int:book_id>')
@login_required
def delete_book(book_id):
    if current_user.role != 'admin':
        return "Access denied."

    book = Book.query.get_or_404(book_id)
    db.session.delete(book)
    db.session.commit()
    flash("Book deleted.", "danger")
    return redirect(url_for('manage_books'))

# Code for recommending a book (lecturer only)
@app.route('/recommend-book', methods=['GET', 'POST'])
@login_required
def recommend_book():
    if current_user.role != 'lecturer':
        return "Access denied."

    form = RecommendForm()
    if form.validate_on_submit():
        rec = Recommendation(
            name=current_user.name,
            email=current_user.email,
            title=form.title.data,
            author=form.author.data,
            program=form.program.data,
            level=form.level.data,
            keywords=form.keywords.data,
            message=form.message.data
        )
        db.session.add(rec)
        db.session.commit()
        flash("Recommendation submitted successfully!", "success")
        return redirect(url_for('recommend_book'))

    return render_template('recommend_book.html', form=form)

# Code for viewing all recommendations made by lecturers (admin only)
@app.route('/recommendations')
@login_required
def recommendations():
    if current_user.role != 'admin':
        return "Access denied."

    recs = Recommendation.query.order_by(Recommendation.timestamp.desc()).all()
    return render_template('recommendations.html', recs=recs)

# Code for accessing lecturer dashboard
@app.route('/lecturer-dashboard')
@login_required
def lecturer_dashboard():
    if current_user.role != 'lecturer':
        return "Access denied."
    return render_template('lecturer_dashboard.html', user=current_user)

# Code for viewing recommendations made by the logged-in lecturer
@app.route('/my-recommendations')
@login_required
def my_recommendations():
    if current_user.role != 'lecturer':
        return "Access denied."
    recs = Recommendation.query.filter_by(email=current_user.email).order_by(Recommendation.timestamp.desc()).all()
    return render_template('my_recommendations.html', recs=recs)

# Code for adding a new user (admin only)
@app.route('/add-user', methods=['GET', 'POST'])
@login_required
def add_user():
    if current_user.role != 'admin':
        flash("Access denied.", "danger")
        return redirect(url_for('dashboard'))

    form = AddUserForm()
    if form.validate_on_submit():
        existing_user = User.query.filter_by(email=form.email.data).first()
        if existing_user:
            flash("A user with this email already exists.", "danger")
        else:
            hashed_pw = generate_password_hash(form.password.data)
            new_user = User(
                name=form.name.data,
                email=form.email.data,
                password=hashed_pw,
                role=form.role.data,
                program=form.program.data,
                level=form.level.data
            )
            db.session.add(new_user)
            db.session.commit()
            flash("✅ User added successfully!", "success")
            return redirect(url_for('add_user'))  # reload form after adding

    return render_template('add_user.html', form=form)

# Code for viewing all users (admin only)
@app.route('/all-books')
@login_required
def all_books():
    if current_user.role != 'admin':
        return "Access denied."

    search_query = request.args.get("q", "")
    page = request.args.get('page', 1, type=int)
    book_query = Book.query

    if search_query:
        book_query = book_query.filter(
            (Book.title.ilike(f"%{search_query}%")) |
            (Book.author.ilike(f"%{search_query}%")) |
            (Book.keywords.ilike(f"%{search_query}%"))
        )

    books = book_query.order_by(Book.title).paginate(page=page, per_page=10)
    return render_template('all_books.html', books=books)


# Error handling for 404 and 403 errors
@app.errorhandler(404)
def page_not_found(e):
    return render_template("page_not_found.html"), 404

@app.errorhandler(403)
def access_denied(e):
    return render_template("access_denied.html"), 403

# Code for lecturer library (lecturer only)
@app.route('/lecturer-library')
@login_required
def lecturer_library():
    if current_user.role != 'lecturer':
        return "Access denied."

    search_query = request.args.get("q", "")
    page = request.args.get('page', 1, type=int)
    book_query = Book.query

    if search_query:
        book_query = book_query.filter(
            (Book.title.ilike(f"%{search_query}%")) |
            (Book.author.ilike(f"%{search_query}%")) |
            (Book.keywords.ilike(f"%{search_query}%"))
        )

    books = book_query.order_by(Book.title).paginate(page=page, per_page=10)

    return render_template("lecturer_library.html", books=books, search=search_query)


# Code for logging out
@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash("✅ You have been logged out successfully.", "success")
    return redirect(url_for('login'))




if __name__ == '__main__':
    app.run(debug=True)
