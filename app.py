import sys
import os
import os.path as op
import pexpect
import hashlib
import datetime
import socket
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
    'name': 'skyfall',
    'engine': 'peewee.MySQLDatabase',
    'user': 'root',
    'passwd': 'brokenstrings',
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

# Global list to hold process objects
harbors = []

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
    name = CharField(unique=True)
    created = DateTimeField(default=datetime.datetime.now)
    ended = DateTimeField(null=True)
    kernel_pid = IntegerField()
    subdomain = CharField(unique=True)
    port = IntegerField()
    root = CharField()
    state = CharField()
    owner = ForeignKeyField(User)
    image = ForeignKeyField(Image)

    def __unicode__(self):
    	return self.name

class KernelAdmin(ModelAdmin):
	columns = ('name', 'created', 'ended', 'kernel_pid', 'subdomain', 'port', 'root', 'state', 'owner', 'image',)

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

# Finds an empty port
def get_open_port():
    print "Opening random socket..."
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("",0))
    print "Listening on random socket..."
    s.listen(1)
    print "Obtaining random port..."
    port = s.getsockname()[1]
    print "Random port obtained at: %s" %port
    s.close()
    return port



# Starts a kernel.
def kernel_start(user, port):
    print "Entering user directory..."
    os.chdir('/home/vagrant/skyfall/files/%s' %user.username)
    print "Generating kernel initiation command..."
    command = '/home/vagrant/.virtualenvs/skyfall/bin/ipython notebook --ip=0.0.0.0 --port=%s --pylab=inline' %port
    print "Kernel creation command: %s" %command
    print "Spawning notebook kernel..."
    process = pexpect.spawnu(command)
    print "Notebook process started with pid: %s" %process.pid
    process.logfile = sys.stdout
    return process


# Stops a kernel.
def kernel_terminate(kernel_pid):
    os.kill(kernel_pid, 0)

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
            workspace_name = new_user.username
            os.chdir('files')
            os.mkdir(workspace_name)
            os.chdir('../')
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
    user_kernels = Kernel.select().where(Kernel.owner == current_user)
    return render_template('kernels.html', user_kernels=user_kernels)

@app.route('/images')
def images_view():
    images = Image.select()
    return render_template('images.html', images=images)

@app.route('/kernels/new', methods=['GET', 'POST'])
def new_kernel_view():
    if request.method == 'POST':
        user = auth.get_logged_in_user()
        i = 'mathharbor/ipython' #request.form["image"]
        image = Image.select().where(Image.name == i)
        name = request.form["name"]
        subdomain = '%s.mathharbor.com' %(name)
        port = get_open_port()
        root = '/home/vagrant/skyfall/files/%s' %user.username
        new_kernel_process = kernel_start(user=user, port=port)
	print "Saving kernel details to the database..."
        new_kernel = Kernel(name=name, owner=user, subdomain=subdomain, port=port, root=root, state='Running', image=image, kernel_pid=new_kernel_process.pid)
	new_kernel.save()
	print "Adding kernel to global kernel list..."
	harbors.append(new_kernel_process)
	return redirect('/kernels')
    return render_template('new_kernel.html')

@app.route('/kernels/kill/<int:kernel_pid>')
def kernel_kill_view(kernel_pid):
    kernel_count = len(harbors)
    i = 0
    while(i < kernel_count):
	print harbors[i].pid
	if harbors[i].pid == kernel_pid:
		harbors[i].terminate(force=True)
		del harbors[i]
	i += 1
    return redirect('/kernels')


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=80)
