import datetime
import hashlib
import os
import bcrypt

from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

class Users(db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key = True)
    #user info
    
    email = db.Column(db.String, nullable = False, unique = True)
    contact_info = db.Column(db.String, nullable = False)
    password_digest = db.Column(db.String, nullable = False)
    #location if we have time for searching purposes

    posts = db.relationship("Posts", cascade = "delete")
    #session info
    session_token = db.Column(db.String, nullable = False, unique = True)
    session_expiration = db.Column(db.DateTime, nullable = False)
    update_token = db.Column(db.String, nullable = False, unique = True)

    def __init__(self, **kwargs):
        self.email = kwargs.get("email")
        self.password_digest = bcrypt.hashpw(kwargs.get("password").encode("utf8"), bcrypt.gensalt(rounds = 13))
        self.contact_info = kwargs.get("contact_info")
        self.renew_session()

    def serialize_posts(self):
        return {
            "posts": [s.serialize() for s in self.posts]
        }

    def serialize_contactinfo(self):
        return {
            "email": self.email,
            "contact_info": self.contact_info
        }


    def _urlsafe_base_64(self):
        return hashlib.sha1(os.urandom(64)).hexdigest()

    def renew_session(self):
        self.session_token = self._urlsafe_base_64()
        self.session_expiration = datetime.datetime.now() + datetime.timedelta(days = 1)
        self.update_token = self._urlsafe_base_64()

    def verify_password(self, password):
        return bcrypt.checkpw(password.encode("utf8"), self.password_digest)

    def verify_session_token(self, session_token):
        return session_token == self.session_token and datetime.datetime.now() < self.session_expiration

    def verify_update_token(self, update_token):
        return update_token == self.update_token
    
def create_user(email, password, contact_info):
    existing_user = Users.query.filter(Users.email == email).first()
    if existing_user:
        return False, None
    user = Users(email = email, password = password, contact_info = contact_info)
    db.session.add(user)
    db.session.commit()
    return True, user

def verify_credentials(email, password):
    existing_user = Users.query.filter(Users.email == email).first()
    if not existing_user:
        return False, None

    return existing_user.verify_password(password), existing_user

def renew_session(update_token):
    existing_user = Users.query.filter(Users.update_token == update_token).first()
    if not existing_user:
        return False, None

    existing_user.renew_session()
    db.session.commit()
    return True, existing_user

def verify_session(session_token):
    return Users.query.filter(Users.session_token == session_token).first()


class Posts(db.Model):
    __tablename__ = "posts"
    id = db.Column(db.Integer, primary_key = True)
    post_title = db.Column(db.String, nullable = False)
    category = db.Column(db.String, nullable = False)
    price = db.Column(db.Integer, nullable = False)
    description = db.Column(db.String, nullable = False)
    image_url = db.Column(db.String, nullable = False)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"))

    def serialize(self):
        user = Users.query.filter_by(id = self.user_id).first()
        return {
            "email": user.email,
            "contact_info": user.contact_info,
            "post_title": self.post_title,
            "category": self.category,
            "price": self.price,
            "description": self.description,
            "image_url": self.image_url
        }

    def __init__(self, **kwargs):
        self.post_title = kwargs.get("post_title")
        self.category = kwargs.get("category")
        self.price = kwargs.get("price")
        self.description = kwargs.get("description")
        self.image_url = kwargs.get("image_url")
        self.user_id = kwargs.get("user_id")
        
