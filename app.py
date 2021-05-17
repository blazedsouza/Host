from flask import Flask, request, jsonify, session, make_response
from flask import render_template
import jwt
import datetime
from functools import wraps
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy
import os
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField
from wtforms.validators import InputRequired, Length
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.fernet import Fernet
from werkzeug.utils import secure_filename
import base64
from flask import send_from_directory
from flask import redirect
import ssl

UPLOAD_FOLDER = 'uploads/'
app = Flask(__name__, template_folder='templates')
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

database_uri = 'postgresql+psycopg2://{dbuser}:{dbpass}@{dbhost}/{dbname}'.format(
    dbuser="postgres",
    dbpass="admin",
    dbhost="localhost",
    dbname="securitydb"
)




app = Flask(__name__)
Bootstrap(app)
app.config['SECRET_KEY'] = 'blaze'
app.config.update(
    SQLALCHEMY_DATABASE_URI=database_uri,
    SQLALCHEMY_TRACK_MODIFICATIONS=False,
)

db = SQLAlchemy(app)
migrate = Migrate(app, db)

class LoginForm(FlaskForm):
    username = StringField('username', validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('password', validators=[InputRequired()])
    remember = BooleanField('remember me')

class RegisterForm(FlaskForm):
    username = StringField('username', validators=[InputRequired(), Length(min=4)])
    password = PasswordField('password', validators=[InputRequired()])

class User(db.Model):
    name = db.Column(db.String(50), primary_key=True)
    password = db.Column(db.String(80))

    def __init__(self, name=None, password=None):
        self.name = name
        self.password = password

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.args.get('token')

        if not token:
            return jsonify({'message' : 'Token is missing!'}), 401

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'])

        except:
            return jsonify({'message' : 'Token is Invalid!'}), 403

        return f(*args, **kwargs)
    
    return decorated

@app.route('/')
def index():
    return render_template('index.html')
    
        
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = RegisterForm()

    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method='sha256')
        new_user = User(name=form.username.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return '<h1>New user created</h1>'
    return render_template('signup.html', form=form)

@app.route('/auth')
@token_required
def authorised(): 
    return 'This is viewable with token'

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        user = User.query.filter_by(name=form.username.data).first()
        if user:
            if check_password_hash(user.password, form.password.data):
                token = jwt.encode({'username' : form.username.data, 'exp' : datetime.datetime.utcnow() + datetime.timedelta(seconds=60)}, app.config['SECRET_KEY'])

                return jsonify({'token' : token.decode('UTF-8')})
        return 'Invalid Username or password'
    return render_template('login.html', form=form)

@app.route("/encrypt", methods=["GET", "POST"])
@token_required
def enc():
    error = None
    if request.method == "POST":
        if request.files:
            blob_saved_file = request.files["file_name"]
            password = request.form["password"]
            encryption(password, blob_saved_file)
            return render_template("index.html")
    return render_template("save-file.html")


@app.route("/decrypt", methods=["GET", "POST"])
def dec():
    error = None
    if request.method == "POST":
        if request.files:
            blob_saved_file = request.files["file_name"]
            password = request.form["password"]
            decryption(password, blob_saved_file)
            return render_template("index.html")
    return render_template("save-file.html")

def encryption(password, file):
    filename = file.filename
    key1 = "12345678abcd"
    key2 = "K4cfTZRo3zAJ6GzmETWKt-OgSqBRpfBd0jow_zWEwyQ="
    new_key = (key1 + password)

    # open file to encrypt

    filepath =  os.path.join(app.config['UPLOAD_FOLDER'],filename)
    
    key3 = "ascii"
    message_bytes = new_key.encode(key3)
    base64_bytes = base64.b64encode(message_bytes)
    base64_message = base64_bytes.decode(key3)
    
    fernet = Fernet(key2)
    encrypted = fernet.encrypt(base64_bytes)
    print("Sensitive key in byte format:",encrypted)

    secure_name = secure_filename(filename)
    file_secure_path = os.path.join(app.config['UPLOAD_FOLDER'],secure_name)
    file.save(file_secure_path)
    with open(file_secure_path, 'rb') as f:
        file = f.read()
        f.close()


    fernet = Fernet(key2)
    encrypted_file = fernet.encrypt(file)

    with open(file_secure_path + ".encrypted",'wb') as f:
        f.write(encrypted_file)
        f.close()
    

def decryption(password, file):
    filename = file.filename
    key1 = "12345678abcd"
    key2 = "K4cfTZRo3zAJ6GzmETWKt-OgSqBRpfBd0jow_zWEwyQ="
    new_key = (key1 + password)

    # open file to encrypt
    filepath =  os.path.join(app.config['UPLOAD_FOLDER'],filename)
    
    key3 = "ascii"
    message_bytes = new_key.encode(key3)
    base64_bytes = base64.b64encode(message_bytes)
    base64_message = base64_bytes.decode(key3)
    
    fernet = Fernet(key2)
    encrypted = fernet.encrypt(base64_bytes)
    print("Sensitive key in byte format:",encrypted)

    secure_name = secure_filename(filename)
    file_secure_path = os.path.join(app.config['UPLOAD_FOLDER'],secure_name)
    file.save(file_secure_path)
    with open(file_secure_path, 'rb') as f:
        file = f.read()
        f.close()


    fernet = Fernet(key2)
    encrypted_file = fernet.decrypt(file)

    with open(file_secure_path.replace(".encrypted",""),'wb') as f:
        f.write(encrypted_file)
        f.close()



if __name__ == '__main__':
    
    app.run(ssl_context=('cert.pem', 'key.pem'))
