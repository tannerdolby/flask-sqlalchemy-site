from flask_jwt_extended import create_access_token
from flask_jwt_extended import get_jwt_identity
from flask_jwt_extended import jwt_required
from flask_jwt_extended import JWTManager
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_login import UserMixin
from sqlalchemy import exc
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from datetime import datetime
from flask import Flask, render_template, flash, redirect, request, session, logging, url_for, Blueprint, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from wtforms import Form, BooleanField, StringField, PasswordField, validators, TextAreaField, IntegerField
from wtforms.validators import DataRequired

# Create flask application
app = Flask(__name__)

auth = Blueprint('auth', __name__)

# Setup the Flask-JWT-Extended extension
app.config["SECRET_KEY"] = "1af&!nfoas0jak51jahd8sk3jasd"
app.config["JWT_SECRET_KEY"] = "8jky62asdsd8nkjggybfjhu98hsdhb509132kjnakdjbif89"
jwt = JWTManager(app)

# Load the SQLAlchemy configuration
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///:memory:"

# Create the SQLAlchemy object and LoginManager object
db = SQLAlchemy(app)

# Form models
class LoginForm(Form):
    username=StringField('username',[validators.DataRequired()])
    password=PasswordField('password',[validators.DataRequired()])

class RegisterForm(Form):
    username = StringField("Username", validators=[validators.Length(min=3, max=25), validators.DataRequired(message="Please Fill This Field")])
    email = StringField("Email", validators=[validators.Email(message="Please enter a valid email address")])
    password = PasswordField("Password", validators=[
        validators.DataRequired(message="Please Fill This Field"),
        validators.EqualTo(fieldname="confirm", message="Your Passwords Do Not Match")
    ])
    confirm = PasswordField("Confirm Password", validators=[validators.DataRequired(message="Please Fill This Field")])  

# Create User Data Model
class User(db.Model):
    """Model to represent Users"""
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    isadmin = db.Column(db.Boolean, nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    def __repr__(self):
        return "<User: {}>".format(self.username)


class Image(db.Model):
    """Model to represent images"""
    __tablename__ = 'image'
    id = db.Column(db.Integer, primary_key=True)
    name=db.Column(db.String(150), unique=True, nullable=False)
    src=db.Column(db.String(200), unique=True, nullable=False)
    alt= db.Column(db.String(200), unique=True, nullable=False)
    url=db.Column(db.String(200), unique=True, nullable=False)

    def __repr__(self):
        return "<Image: {}>".format(self.name)

    # Create a many-to-many relationship with User and many images
    # Establish a relationship between the tables with a foreign key! (Referring to the 'user' table)
    #user_id = db.Column(db.Integer, db.ForeignKey('user.user_id'), nullable=False)

class Liked(db.Model):
    """Model to represent liked images"""
    __tablename__ = 'Liked'
    id = db.Column(db.Integer, primary_key=True)
    name=db.Column(db.String(150), nullable=False)
    src=db.Column(db.String(200), nullable=False)
    alt= db.Column(db.String(200), nullable=False)
    url = db.Column(db.String(200), nullable=False)
    user_id = db.Column(db.Integer, nullable=False)

    def __repr__(self):
        return "<Image: {}>".format(self.name)

# Run the SQLAlchemy.create_all() method to create tables and database
db.create_all()

# Create a One-To-Many relationship where "one" user object can have
# many "liked" or "added-to-collection" images

# Create some images to populate main home feed
img1 = Image(
            id=1,
            name="Grayscale Paintings",
            src= "/images/pexels-adrianna-calvo.jpg",
            alt="Grayscale photography of paintings in an auction or musuem",
            url="https://www.pexels.com/photo/grayscale-photography-of-paintings-21264"
        )
img2 = Image(
            id=2,
            name= "Silhoette of Trees",
            src= "/images/pexels-min-an.jpg",
            alt= "Silhouette photo of trees",
            url="https://www.pexels.com/photo/silhouette-photo-of-trees-962312/"
        )
img3 = Image(
            id=3,
            name="Assorted Paintings",
            src="/images/pexels-medhat-ayad.jpg",
            alt= "Minimalist design of paintings placed in a row layout with 3 in each row on a white wall.",
            url="https://www.pexels.com/photo/assorted-paintings-383568/"
        )
img4 = Image(
            id=4,
            name= "Brown Wooden Framed Painting on Wall",
            src="/images/pexels-daria-shevtsova.jpg",
            alt= "Old framed picture with fruit in a bowl",
            url="https://www.pexels.com/photo/brown-wooden-framed-painting-on-a-wall-3597326/"
        )
img5 = Image(
            id=5,
            name= "Gray metal decorative cubes",
            src="/images/pexels-oleg-magni.jpg",
            alt= "Gray metal decorative cubes",
            url="https://www.pexels.com/photo/gray-metal-cubes-decorative-1005644/"
        )
img6 = Image(
            id=6,
            name= "Interior design of a building",
            src="/images/pexels-ena-marinkovic.jpg",
            alt= "Interior design of a building",
            url="https://www.pexels.com/photo/interior-design-of-a-building-3697742/"
        )

db.session.add(img1)
db.session.add(img2)
db.session.add(img3)
db.session.add(img4)
db.session.add(img5)
db.session.add(img6)
db.session.commit()

# Create some test users
tanner = User(
    username="tanner",
    password=generate_password_hash("foobar", method='sha256'),
    email="t@gmail.com",
    isadmin=True
)

guest = User(
    username="guest",
    password=generate_password_hash("foobar", method='sha256'),
    email="guest@gmail.com",
    isadmin=False
)

# Insert Users into DB for current session and commit changes
db.session.add(tanner)
db.session.add(guest)
db.session.commit()

# Accessing all the DB records, using User.query.all() 
# print(User.query.all())
# [User - id: 1, username: tcdolby, email: tannercdolby@gmail.com, isadmin: True, User - id: 2, username: guest, email: gues@gmail.com, isadmin: False]

# Do a bit of filtering records with query.filter_by()
# print(User.query.filter_by(username="tanner").first())
# User - id: 1, username: tcdolby, email: tannercdolby@gmail.com, isadmin: True

# Helpers

@app.context_processor
def inject_date():
    return {
        "date": datetime.utcnow()
    }

@app.context_processor
def inject_name():
    return {
        "fname": "Tanner",
        "lname": "Dolby"
    }

# Routing

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        title = request.form.get("title")
        photo = Image.query.filter_by(name=title).first()

        img = Liked(
            id=photo.id,
            name=photo.name,
            src=photo.src,
            alt=photo.alt,
            url=photo.url,
            user_id= session['id']
        )
        
        if session['logged_in'] == True:
            try:
                db.session.add(img)
                for image in Liked.query.all():
                    if image.id == img.id:
                        img.id += 10
                        db.session.add(img)
            except exc.IntegrityError as e:
                print("Error", e)
            finally:
                db.session.commit()

        liked = Liked.query.all()
        ct = 0
        for item in liked:
            if item.user_id == session['id']:
                ct += 1

        return redirect(url_for('profile', title=title, ct=ct, access_token=jsonify(access_token=session['username'])))
    return render_template('index.html', photos=Image.query.all(), mylist=Liked.query.all())

@jwt_required()
@app.route('/profile/', methods=['GET', 'POST'])
def profile():
    if session['logged_in'] is False:
        return redirect(url_for('login'))
    
    if session['token'] != '':
        print("token exists!")

    photo = request.args.get("title", None)
    count = request.args.get('ct', 0)
    likedAmount = len(Liked.query.all())

    return render_template('profile.html', title=photo, count=count, photos=Liked.query.all(), likedLen=likedAmount)

@app.route('/register/', methods = ['GET', 'POST'])
def register():
    # Creating RegistrationForm class object
    form = RegisterForm(request.form)

    # Checking method="POST" and form is valid or not.
    if request.method == 'POST':
        # generate hashed password
        hashed_password = generate_password_hash(form.password.data, method='sha256')
        # create new user model object
        new_user = User(
            username = form.username.data, 
            password = hashed_password,
            email = form.email.data,
            isadmin = False)
        msg = ''
        if new_user !=  '<User None>':
            # saving user object into data base with hashed password
            db.session.add(new_user)
            print("New user created: {}".format(new_user))
            msg = 'Account successfully created!'
            db.session.commit()
        else:
            print("Unable to create user. That user already exists!")
            msg = "Unable to create User. That account already exists!"

        # if registration successful, then redirecting to login Api
        return redirect(url_for('login', msg=msg))
    else:
        # if method is Get, than render registration form
        return render_template('register.html', form=form)

# Login API endpoint implementation
@app.route('/login/', methods = ['GET', 'POST'])
def login():
    # Creating Login form object
    form = LoginForm(request.form)
    # verifying that method is post and form is valid
    if request.method == 'POST':
        # checking that user is exist or not by username
        user = User.query.filter_by(username=form.username.data).first()

        if user:
            print(user, "USER FOUND")
            if check_password_hash(user.password, form.password.data) or user.password == form.password.data:
                # if password is matched, allow user to access and save email and username inside the session
                session['logged_in'] = True
                session['email'] = user.email
                session['username'] = user.username
                session['isadmin'] = user.isadmin
                session['created_at'] = user.created_at
                session['id'] = user.id            
                access_token = create_access_token(identity=user.username)
                session['token'] = access_token
                
                # After successful login, redirecting to home page
                return redirect(url_for('index'))
            else:
                # if password is incorrect , redirect to login page
                print("Incorrect!")
                return redirect(url_for('login'))
        else:
            print("User doesn't exist!")

    # rendering login page
    return render_template('login.html', form=form)

@app.route('/admin-dashboard/')
def admindash():
    if session['isadmin'] == None or session['isadmin'] is False:
        return redirect(url_for('index'))
    if session['logged_in'] == False:
        return redirect(url_for('index'))
        if session['isadmin'] == True:
            return redirect(url_for('index'))

    return render_template('admin-dash.html', users=User.query.all(), images=Image.query.all(), liked=Liked.query.all())

@app.route('/contact')
def contact():
    return render_template('contact.html')

@app.route('/logout/')
def logout():
    session['logged_in'] = False
    session['token'] = ''
    session['isadmin'] = False
    return redirect(url_for('index'))

# CRUD Operations for Admin users

@app.route('/admin/create/user', methods=['GET', 'POST'])
def create_user():
    b = False
    if (request.form.get('isadmin') == 'True'):
        b = True
    user = User(
            username=request.form.get('username'),
            password=request.form.get('password'),
            email=request.form.get('email'),
            isadmin=b
        )

    if request.method == 'POST':
        db.session.add(user)
        db.session.commit()
        print("User created: {}".format(user.username))
        users = User.query.all()
        return redirect(url_for('admindash', users=users))

    return render_template('create-user.html', user=user, type="User")
        

@app.route('/admin/create/image', methods=['GET', 'POST'])
def create_image():
    image = Image(
                name=request.form.get('name'),
                src=request.form.get('src') or "",
                alt=request.form.get('alt'),
                url=request.form.get('url')
            )

    if request.method == 'POST':
        db.session.add(image)
        db.session.commit()
        print("Image created: {}".format(image.name))
        images = Image.query.all()
        return redirect(url_for('admindash', images=images))
    return render_template('create-image.html', image=image, type="Image")

@app.route('/admin/edit/user/<id>', methods=['GET', 'POST', 'PUT'])
def update_user(id):
    user = User.query.filter_by(id=id).first()
    if request.form.get('username') != None:
        user.username = request.form.get('username')
        user.email = request.form.get('email')
        if request.form.get('isadmin') == 'True':
            user.isadmin = True
        else:
            user.isadmin = False
        db.session.commit()
        print("Updating record")

        return redirect(url_for('admindash', users=User.query.all()))

    return render_template('update-user.html', username=user.username, email=user.email, isadmin=user.isadmin)

@app.route('/admin/edit/image/<id>', methods=['GET', 'POST', 'PUT'])
def update_image(id):
    image = Image.query.filter_by(id=id).first()

    if request.form.get('name') != None:
        image.name = request.form.get('name')
        image.src = request.form.get('src')
        image.alt = request.form.get('alt')
        image.url = request.form.get('url')
        db.session.commit()
        print("Updating record")

        return redirect(url_for('admindash', users=Image.query.all()))

    return render_template('update-image.html', name=image.name, src=image.src, alt=image.alt, url=image.url)
        

@app.route('/admin/delete/user/<id>', methods=['GET', 'DELETE'])
@app.route('/admin/delete/image/<id>', methods=['GET', 'DELETE'])
def delete(id):
    user = User.query.filter_by(id=id).first()
    image = Image.query.filter_by(id=id).first()

    if user and request.path == '/admin/delete/user/' + id:
        try:
            db.session.delete(user)
            db.session.commit()
            print("User: {} deleted".format(id))
        except:
            print("Error deleting record!")

        return redirect(url_for('admindash'))
    
    if image and request.path == '/admin/delete/image/' + id:
        try:
            db.session.delete(image)
            db.session.commit()
            print("Image: {} deleted".format(id))
        except:
            print("Error deleting record!")
        return redirect(url_for('admindash'))

    # get an updated list of User and Image records from DB
    users = User.query.all()
    images = Image.query.all()

    return render_template('admin-dash.html', users=users, images=images)

if __name__ == '__main__':
    app.debug = True
    app.run()