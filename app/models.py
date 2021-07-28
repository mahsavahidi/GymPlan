import datetime
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import create_engine
from passlib.hash import sha256_crypt

db = SQLAlchemy()


def init_app(app):
    db.app = app
    db.init_app(app)
    return db


def create_tables(app):
    engine = create_engine(app.config['SQLALCHEMY_DATABASE_URI'])
    db.metadata.create_all(engine)
    return engine


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(255), unique=False)
    last_name = db.Column(db.String(255), unique=False)
    email = db.Column(db.String(255), unique=False)
    password = db.Column(db.String(255), unique=False)
    mellicode = db.Column(db.String(255), unique=False)
    mobile = db.Column(db.String(255), unique=True)
    status = db.Column(db.Boolean(255), unique=False)
    authenticated = db.Column(db.Boolean, default=False)
    api_key = db.Column(db.String(255), unique=False)

    blacklist = db.Column(db.Boolean, unique=False)

    def encode_api_key(self):
        self.api_key = sha256_crypt.hash(self.mobile + str(datetime.datetime.utcnow()))

    def encode_password(self):
        self.password = sha256_crypt.hash(self.password)

    def is_authenticated(self):
        return self.authenticated

    def get_id(self):
        return self.id

    def is_active(self):
        return True

    def black_list(self):
        self.blacklist = False

    def __repr__(self):
        return '<User %r>' % (self.mobile)

    def to_json(self):
        return {
            'first_name': self.first_name,
            'last_name': self.last_name,
            'mobile': self.mobile,
            'email': self.email,
            'id': self.id,
            'api_key': self.api_key,
        }


class Confirmation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    mobile = db.Column(db.String(255), unique=False)
    confirmation_code = db.Column(db.String(255), unique=False)
    is_confirmed = db.Column(db.Boolean, default=False)