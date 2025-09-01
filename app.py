from flask import Flask, request, jsonify
from datetime import datetime, timedelta
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
from flask_jwt_extended import create_access_token, JWTManager, jwt_required, get_jwt_identity
from sqlalchemy.dialects.postgresql import UUID
import os
import uuid

load_dotenv()

app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URI')
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY')
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(minutes=60)

db = SQLAlchemy(app)
jwt = JWTManager(app)

@jwt.expired_token_loader
def expired_token_callback(jwt_header, jwt_payload):
    return jsonify({
        "error": "token_expired",
        "message": "Your access token has expired. Please login again."
    }), 401

@jwt.invalid_token_loader
def invalid_token_callback(error):
    return jsonify({
        "error": "invalid_token",
        "message": "The token is invalid."
    }), 401

@jwt.unauthorized_loader
def missing_token(err):
    return jsonify({
        "error": "token_missing",
        "message": "Please login to access this resource."
    }), 401

#model
class User(db.Model):
    id = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    fullname = db.Column(db.String(50), nullable=False)
    username = db.Column(db.String(50), nullable=False, unique=True)
    password = db.Column(db.String(200), nullable=False)
    created_on = db.Column(db.DateTime, default=datetime.utcnow)
    updated_on = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    posts = db.relationship("Post", backref="author", lazy=True, cascade="all, delete-orphan")
    comments = db.relationship("Comment", backref="author", lazy=True, cascade="all, delete-orphan")

class Post(db.Model):
    id = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)

    title = db.Column(db.String(255), nullable=False)  # short text
    description = db.Column(db.Text, nullable=False)   # longer content
    image = db.Column(db.String(500), nullable=True)   # store image URL or path

    user_id = db.Column(UUID(as_uuid=True), db.ForeignKey('user.id'), nullable=False, index=True)
    likes = db.Column(db.Integer, default=0)
    noofcomments = db.Column(db.Integer, default=0)
    created_on = db.Column(db.DateTime, default=datetime.utcnow)
    updated_on = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    comments = db.relationship(
        "Comment",
        backref="post",
        lazy=True,
        cascade="all, delete-orphan"
    )

class Comment(db.Model):
    id = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    content = db.Column(db.Text, nullable=False)
    post_id = db.Column(UUID(as_uuid=True), db.ForeignKey("post.id"), nullable=False, index=True)
    user_id = db.Column(UUID(as_uuid=True), db.ForeignKey('user.id'), nullable=False, index=True)
    created_on = db.Column(db.DateTime, default=datetime.utcnow)

with app.app_context():
    db.create_all()

@app.route('/', methods=['GET'])
def home():
    return "this is home", 200

# Register
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json(silent=True) or {}
    username = data.get('username')
    fullname = data.get('fullname')
    password = data.get('password')

    if not username or not password or not fullname:
        return jsonify({"message": "Missing required fields"}), 400

    if User.query.filter_by(username=username).first():
        return jsonify({"message": "User already exists"}), 400

    hashed_password = generate_password_hash(password)
    try:
        new_user = User(fullname=fullname, username=username, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return jsonify({
            "message": "User registered successfully",
            "status": True,
            "type": "registration",
            "error_status": {"error_code": "0"}
        }), 201
    except Exception:
        db.session.rollback()
        return jsonify({
            "message": "Something went wrong, please try after sometime",
            "status": False,
            "type": "registration",
            "error_status": {"error_code": "500"}
        }), 500

# Login
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json(silent=True) or {}
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({"message": "Missing fields"}), 400

    user = User.query.filter_by(username=username).first()
    if user and check_password_hash(user.password, password):
        token = create_access_token(identity=str(user.id))
        return jsonify({
            "message": "login success",
            "access_token": token,
            "username": user.username
        }), 200

    return jsonify({"message": "Invalid username or password"}), 401

# Forget password
@app.route('/forget-password', methods=['POST'])
def forget_password():
    data = request.get_json(silent=True) or {}
    username = data.get('username')
    new_password = data.get('password')

    if not username or not new_password:
        return jsonify({"message": "Missing fields"}), 400

    user = User.query.filter_by(username=username).first()
    if not user:
        return jsonify({"message": "User not exist"}), 404

    user.password = generate_password_hash(new_password)
    try:
        db.session.commit()
        return jsonify({"message": "Password reset successfully"}), 200
    except Exception:
        db.session.rollback()
        return jsonify({"message": "Database error"}), 500

# My posts
@app.route('/my-posts', methods=['GET'])
@jwt_required()
def get_all_posts():
    # identity is a stringified UUID; convert to UUID for comparisons
    user_uuid = uuid.UUID(get_jwt_identity())
    raw_posts = Post.query.filter_by(user_id=user_uuid).all()
    posts = [{
        "id": str(p.id),
        "content": p.content,
        "created_on": p.created_on.isoformat()
    } for p in raw_posts]
    return jsonify({"posts": posts, "message": "success"}), 200

# Create post
@app.route('/create-post', methods=['POST'])
@jwt_required()
def create_post():
    data = request.get_json(silent=True) or {}
    content = data.get("content")
    if not content:
        return jsonify({"message": "Missing content"}), 400

    user_uuid = uuid.UUID(get_jwt_identity())

    new_post = Post(content=content, user_id=user_uuid)
    try:
        db.session.add(new_post)
        db.session.commit()
        return jsonify({"message": "Post created", "post_id": str(new_post.id)}), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({"message": "Error creating the post", "error": str(e)}), 500

# Update post
@app.route('/update-post/<uuid:post_id>', methods=['PUT'])
@jwt_required()
def update_post(post_id):
    data = request.get_json(silent=True) or {}
    content = data.get('content')
    if not content:
        return jsonify({"message": "Missing content"}), 400

    user_uuid = uuid.UUID(get_jwt_identity())
    post = Post.query.get(post_id)
    if not post:
        return jsonify({"message": "Post not found"}), 404

    if post.user_id != user_uuid:
        return jsonify({"message": "This is not your post"}), 403

    try:
        post.content = content
        db.session.commit()
        return jsonify({"message": "Post updated"}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({"message": "Error updating the post", "error": str(e)}), 500

# Delete post
@app.route('/delete-post/<uuid:post_id>', methods=['DELETE'])
@jwt_required()
def delete_post(post_id):
    post = Post.query.get(post_id)
    if not post:
        return jsonify({"message": "Post not found"}), 404

    user_uuid = uuid.UUID(get_jwt_identity())
    if post.user_id != user_uuid:
        return jsonify({"message": "This is not your post"}), 403

    try:
        db.session.delete(post)
        db.session.commit()
        return jsonify({"message": "Post deleted"}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({"message": "Error deleting the post", "error": str(e)}), 500

# View all comments for a post
@app.route('/all-comments/<uuid:post_id>', methods=['GET'])
@jwt_required()
def get_all_comments(post_id):
    raw_comments = Comment.query.filter_by(post_id=post_id).all()
    comments = [{
        "id": str(c.id),
        "content": c.content,
        "created_on": c.created_on.isoformat(),
        "user_id": str(c.user_id)
    } for c in raw_comments]
    return jsonify({"comments": comments}), 200

# Create comment
@app.route('/create-comment/<uuid:post_id>', methods=['POST'])
@jwt_required()
def create_comment(post_id):
    data = request.get_json(silent=True) or {}
    content = data.get("content")
    if not content:
        return jsonify({"message": "Missing comment content"}), 400

    user_uuid = uuid.UUID(get_jwt_identity())
    post = Post.query.get(post_id)
    if not post:
        return jsonify({"message": "Post not found"}), 404

    new_comment = Comment(content=content, post_id=post_id, user_id=user_uuid)
    try:
        db.session.add(new_comment)
        # If you keep a counter, update it here (optional)
        post.noofcomments = (post.noofcomments or 0) + 1
        db.session.commit()
        return jsonify({"message": "Comment created", "comment_id": str(new_comment.id)}), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({"message": "Some error occurred", "error": str(e)}), 500

# Delete comment
@app.route('/delete-comment/<uuid:comment_id>', methods=['DELETE'])
@jwt_required()
def delete_comment(comment_id):
    user_uuid = uuid.UUID(get_jwt_identity())
    comment = Comment.query.get(comment_id)
    if not comment:
        return jsonify({"message": "Comment not found"}), 404

    post = Post.query.get(comment.post_id)
    if not post:
        return jsonify({"message": "Post not found"}), 404

    # Author of the comment OR author of the post can delete
    if comment.user_id != user_uuid and post.user_id != user_uuid:
        return jsonify({"message": "Not authorized to delete this comment"}), 403

    try:
        db.session.delete(comment)
        # keep counter in sync if you're using it
        if post.noofcomments and post.noofcomments > 0:
            post.noofcomments -= 1
        db.session.commit()
        return jsonify({"message": "Comment deleted"}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({"message": "Error deleting comment", "error": str(e)}), 500

if __name__ == "__main__":
    app.run(debug=True)
