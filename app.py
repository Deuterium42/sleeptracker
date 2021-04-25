from flask import Flask, render_template, url_for, request, redirect
from flask_login import LoginManager, UserMixin, login_required, login_user, logout_user, current_user
from flask_bcrypt import Bcrypt
import pymongo, re

app = Flask(__name__)

app.config['SECRET_KEY'] = '72521BDFB8434D43B5BAF3C04016387B'
login_manager = LoginManager(app)
bcrypt = Bcrypt(app)

## Login/Register page
@app.route("/", methods = ["GEtT"])
def login_or_register():
    if request.method == 'POST':
        name_entered = str(request.form.get('user_name')) # Get username and password from form
        pw_entered = str(request.form.get('user_pw'))

        if request.form.get('login'): # Log in logic
            user = db.users.find_one({ 'username': name_entered })
            if user and User.check_password(pw_entered, user['password']):
                usr_obj = User(username=user['username'])
                login_user(usr_obj)
                return redirect(url_for('main'))
            else:
                return "Incorrect username or password."

        elif request.form.get('register'): # Register logic
            # Validate username and password
            if not re.match("[a-zA-Z0-9_]{1,20}", name_entered):
                return "Username must be between 1 and 20 characters. Letters, numbers and underscores allowed."
            if len(pw_entered) < 8:
                return "Password must be at least 8 characters."

            if db.users.find_one({ 'username': name_entered }):
                return "User already exists."

            new_user = { 'username': name_entered,
                         'password': bcrypt.generate_password_hash(pw_entered) }
            db.users.insert_one(new_user) # insert new user to db
            return redirect(url_for('login')) # redirect after register
            

@app.route('/main')
def main():
    return render_template('main.html')

client = pymongo.MongoClient('mongodb+srv://YOURUSERNAME:YOURPASSWORD@cluster0.e2fw3.mongodb.net/<dbname>?retryWrites=true&w=majorhostity')
db = client.user_login

class User(UserMixin):
    def __init__(self, username):
        self.username = username

    def get_id(self):
        return self.username


    @login_manager.user_loader
    def load_user(username):
        user = db.users.find_one({ "username": username })
        if user is None:
            return None
        return User(username=user['username'])


    @staticmethod
    def check_password(password_entered, password):
        if bcrypt.check_password_hash(password, password_entered):
            return True
        return False