from flask import Flask
# flask-peewee bindings
from flask_peewee.db import Database
import datetime
from peewee import *

# configure our database
DATABASE = {
    'name': 'dev.db',
    'engine': 'peewee.SqliteDatabase',
}

DEBUG = True
SECRET_KEY = 'ssshhhh'
app = Flask(__name__)
app.config.from_object(__name__)

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


class Kernel(db.Model):
    message = TextField()
    created = DateTimeField(default=datetime.datetime.now)


if __name__ == '__main__':
    app.run(host='0.0.0.0')