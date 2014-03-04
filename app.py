import os
import os.path as op
import subprocess
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
class Profile(db.Model):
	name = TextField()
	description = TextField()
	command = TextField()

	def __unicode__(self):
		return self.name

class ProfileAdmin(ModelAdmin):
	columns = ('name', 'description', 'command',)


# a model for storing per-user notebook kernels.
class Kernel(db.Model):
    name = TextField()
    created = DateTimeField(default=datetime.datetime.now)
    ended = DateTimeField()
    subdomain = TextField(unique=True)
    port = IntegerField()
    root = TextField()
    owner = ForeignKeyField(User)
    profile = ForeignKeyField(Profile)

    def __unicode__(self):
    	return self.name

class KernelAdmin(ModelAdmin):
	columns = ('name', 'created', 'ended', 'subdomain', 'port', 'root', 'owner', 'profile',)

# subclass the admin so that it recognizes our super-user.
class CustomAdmin(Admin):
    def check_user_permission(self, user):
        return user.is_superuser



#Initialize auth and admin modules.

auth = CustomAuth(app, db)
admin = CustomAdmin(app, auth)
admin.register(User, UserAdmin)
admin.register(Kernel, KernelAdmin)
admin.register(Profile, ProfileAdmin)
admin.setup()

# App routes.

@app.route('/')
def index_view():
	return render_template('layout.html')


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)