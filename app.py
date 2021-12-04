import json
import os
from db import create_user, db
from db import verify_credentials, db
from db import renew_session, db
from db import verify_session, db
from flask import Flask
from flask import request
from db import Users
from db import Posts

app = Flask(__name__)
db_filename = "thriftaca.db"

app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///%s" % db_filename
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SQLALCHEMY_ECHO"] = True

db.init_app(app)
with app.app_context():
    db.create_all()


# routes starting here
def success_response(data, code = 200):
    return json.dumps(data), code

def failure_response(message, code = 404):
    return json.dumps({"error": message}), code

def extract_token(request):
    token = request.headers.get("Authorization")
    if token is None:
        return False, "Missing authorization header"
    token = token.replace("Bearer", "").strip()
    return True, token

@app.route("/register/", methods=["POST"])
def register_account():
    body = json.loads(request.data)
    email = body.get("email")
    password = body.get("password")
    contact_info = body.get("contact_info")

    if email is None or password is None:
        return failure_response("Invalid email or password", 400)
    if contact_info is None:
        return failure_response("Missing contact_info", 400)
    
    created, user = create_user(email, password, contact_info)
    if not created:
        return failure_response("User already exists", 403)

    return success_response({
        "session_token": user.session_token,
        "session_expiration": str(user.session_expiration),
        "update_token": user.update_token
    }, 201)

@app.route("/login/", methods=["POST"])
def login():
    body = json.loads(request.data)
    email = body.get("email")
    password = body.get("password")

    if email is None or password is None:
        return failure_response("Invalid email or password", 400)
    
    valid_creds, user = verify_credentials(email, password)
    if not valid_creds:
        return failure_response("Invalid email or password")
    
    return success_response({
        "session_token": user.session_token,
        "session_expiration": str(user.session_expiration),
        "update_token": user.update_token
    })

@app.route("/session/", methods=["POST"])
def update_session():
    success, update_token = extract_token(request)

    if not success:
        return failure_response(update_token)
    
    valid, user = renew_session(update_token)

    if not valid:
        return failure_response("Invalid update token")
    
    return success_response({
        "session_token": user.session_token,
        "session_expiration": str(user.session_expiration),
        "update_token": user.update_token
    })

@app.route("/post/", methods=["POST"])
def create_post():
    success, session_token = extract_token(request)
    
    if not success:
        return failure_response(session_token)

    valid = verify_session(session_token)

    if not valid:
        return failure_response("Invalid session token")

    current_user = Users.query.filter(Users.session_token == session_token).first()

    body = json.loads(request.data)
    post_title = body.get("post_title")
    if post_title is None:
        return failure_response("Missing post_title", 400)
    category = body.get("category")
    if category is None:
        return failure_response("Missing category", 400)
    price = body.get("price")
    if price is None:
        return failure_response("Missing price", 400)
    description = body.get("description")
    if description is None:
        return failure_response("Missing description", 400)
    image_url = body.get("image_url")
    if image_url is None:
        return failure_response("Missing image_url", 400)
    new_post = Posts(user_id = current_user.id, post_title = post_title, category = category, price = price, description = description, image_url = image_url)
    db.session.add(new_post)
    db.session.commit()
    return success_response(new_post.serialize(), 201)

@app.route("/get/")
def get_posts():
    return success_response(
        {"posts": [c.serialize() for c in Posts.query.all()]}
    )

@app.route("/get/<string:email>/")
def get_user_posts(email):
    user = Users.query.filter_by(email = email).first()
    if user is None:
        return failure_response("User not found")
    return success_response(user.serialize_posts())

@app.route("/get/<int:user_id>/")
def get_user_info(user_id):
    user = Users.query.filter_by(id = user_id).first()
    if user is None:
        return failure_response("User not found")
    return success_response({
        "email": user.email,
        "contact_info": user.contact_info
    })

@app.route("/get/category/<string:category>/")
def get_category_posts(category):
    posts = Posts.query.filter_by(category = category).all()
    if posts is None:
        return failure_response("No posts for this category")
    result_dict = [s.serialize() for s in posts]
    return success_response(result_dict)

if __name__ == "__main__":
    port = os.environ.get("PORT", 5000)
    app.run(host="0.0.0.0", port=port)
