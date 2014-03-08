import os
import os.path as op
import hashlib
import datetime
from flask import Flask, url_for, redirect, render_template, request, session, flash

from flask_peewee.auth import Auth
from flask_peewee.auth import BaseUser
from flask_peewee.db import Database
from peewee import *
from flask_peewee.admin import Admin
from flask_peewee.admin import ModelAdmin

from flask_debugtoolbar import DebugToolbarExtension

# configure our database
DATABASE = {
    'name': 'dev.db',
    'engine': 'peewee.SqliteDatabase',
}

DEBUG = True
SECRET_KEY = 'ssshhhh'
app = Flask(__name__)
app.config.from_object(__name__)
app.config['DEBUG_TB_INTERCEPT_REDIRECTS'] = False
app.config['DEBUG_TB_PROFILER_ENABLED'] = True

# instantiate the db wrapper
db = Database(app)

toolbar = DebugToolbarExtension(app)

# Models

# create our custom user model note that we're mixing in the BaseModel in order to
# use the default auth methods it implements, "set_password" and "check_password"
class User(db.Model, BaseUser):
    username = CharField()
    password = CharField()
    email = CharField()
    name = CharField()
    active = BooleanField(default=True)
    is_superuser = BooleanField(default=False)

    def __unicode__(self):
        return self.username

# create a modeladmin for it
class UserAdmin(ModelAdmin):
    columns = ('username', 'email', 'password', 'name', 'is_superuser',)


# subclass Auth so we can return our custom classes
class CustomAuth(Auth):
    def get_user_model(self):
        return User

    def get_model_admin(self):
        return UserAdmin

# a model for storing IPython profiles.
class Image(db.Model):
	name = CharField()
	description = TextField()

	def __unicode__(self):
		return self.name

class ImageAdmin(ModelAdmin):
	columns = ('name', 'description', )


# a model for storing per-user notebook kernels.
class Kernel(db.Model):
    name = CharField()
    created = DateTimeField(default=datetime.datetime.now)
    ended = DateTimeField(null=True)
    subdomain = CharField(unique=True)
    kernel_id = CharField()
    port = IntegerField()
    root = CharField()
    state = CharField()
    owner = ForeignKeyField(User)
    image = ForeignKeyField(Image)

    def __unicode__(self):
    	return self.name

class KernelAdmin(ModelAdmin):
	columns = ('name', 'created', 'ended', 'subdomain', 'port', 'root', 'owner', 'image',)

# subclass the admin so that it recognizes our super-user.
class CustomAdmin(Admin):
    def check_user_permission(self, user):
        return user.is_superuser



#Initialize auth and admin modules.

auth = CustomAuth(app, db)
admin = CustomAdmin(app, auth)
admin.register(User, UserAdmin)
admin.register(Kernel, KernelAdmin)
admin.register(Image, ImageAdmin)
admin.setup()

# Kernel methods.

def kernel_start(user, name, subdomain, port, root, profile):
    kernel_pid = os.spawnl(os.P_NOWAIT, 'ipython notebook')
    new_kernel = Kernel(name=name, owner=user, subdomain=subdomain, port=port, root=root, state='Running', profile=profile, kernel_pid=kernel_pid)
    new_kernel. save()
    return new_kernel

# App routes.

@app.route('/')
def index_view():
    if auth.get_logged_in_user():
        return redirect('/kernels')
    else:
        return render_template('index.html')

@app.route('/register', methods=['POST', 'GET'])
def register_view():
    if request.method == 'POST':
        name = request.form["name"]
        email = request.form["email"]
        username = request.form["username"]
        password = request.form["password"]
        # implement a check here, to search for existing users with the same email/username.
        try:
            check_user = User.get(username=username)
            return redirect('/register')
        except User.DoesNotExist:
            new_user = User(name=name, email=email, username=username)
            new_user.set_password(password)
            new_user.save()
            auth.login_user(new_user)
            return redirect('/')
    return render_template('register.html')

@app.route('/login', methods=['POST', 'GET'])
def login_view():
    if request.method == 'POST':
        username = request.form["username"]
        password = request.form["password"]
        current_user = auth.authenticate(username, password)
        if current_user == False:
            return redirect('/login')
        else:
            auth.login_user(current_user)
            return redirect('/')
    return render_template('login.html')

@app.route('/kernels')
def kernels_view():
    current_user = auth.get_logged_in_user()
    running_user_kernels = Kernel.select().where(Kernel.owner == current_user and Kernel.state == 'Running')
    stopped_user_kernels = Kernel.select().where(Kernel.owner == current_user and Kernel.state == 'Stopped')
    return render_template('kernels.html', running_user_kernels=running_user_kernels, stopped_user_kernels=stopped_user_kernels)

@app.route('/kernel_new')
def new_kernel_view():
    user = auth.get_logged_in_user()
    profile = Profile.select().where(Profile.name == 'Default')
    name = 'devtestthree'
    subdomain = '%s.mathharbor.com' %(name)
    port = 7000
    root = '/files/devtestthree'
    new_kernel = kernel_start(user=user, name=name, subdomain=subdomain, port=port, root=root, profile=profile)
    return redirect('/kernels')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)