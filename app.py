from flask import Flask, request, jsonify
from datetime import datetime, timedelta
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
from flask_jwt_extended import create_access_token, JWTManager, jwt_required, get_jwt_identity
import os

load_dotenv()

app= Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI']= os.getenv('DATABASE_URI')
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY')
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(minutes=60)
db= SQLAlchemy(app)
jwt= JWTManager(app)

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
        "error":"token missing",
        "message":"request to login again"
    }), 400

#user model
class User(db.Model):
    id = db.Column(db.Integer, primary_key= True)
    username = db.Column(db.String(200) , nullable= False)
    password = db.Column(db.String(200), nullable= False)
    created_on = db.Column(db.DateTime, default= datetime.utcnow)
    posts = db.relationship("Post", backref="author", lazy=True)
    comments = db.relationship("Comment", backref='author', lazy= True)
#post model
class Post(db.Model):
    id = db.Column(db.Integer, primary_key= True)
    text = db.Column(db.Text, nullable= False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable= False)
    likes = db.Column(db.Integer, default=0)
    created_on = db.Column(db.DateTime, default= datetime.utcnow)
    comments = db.relationship("Comment", backref='post', lazy=True)
#comment model
class Comment(db.Model):
    id = db.Column(db.Integer, primary_key= True)
    text= db.Column(db.Text, nullable = False)
    created_on = db.Column(db.DateTime, default= datetime.utcnow)
    post_id = db.Column(db.Integer, db.ForeignKey("post.id"), nullable= False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable= False)

with app.app_context():
    db.create_all()

#home route
@app.route('/', methods= ['GET'])
def home():
    return "this is home", 200

#register route
@app.route('/register', methods= ['POST'])
def register():
    username= request.form.get('username')
    password = request.form.get('password')
    #print(username, password)
    if not username or not password:
        return jsonify({"message": "one field missing"}), 400
    exuser= User.query.filter_by(username=username).first()
    if exuser:
        return jsonify({"message": "user already exist"}), 400
    hashed_password= generate_password_hash(password)
    try:
        new_user = User(
        username= username,
        password= hashed_password
        )
        db.session.add(new_user)
        db.session.commit()
        return jsonify({"message": "Success! User added to it"}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({"message":"Error adding the user"}), 500

#login route
@app.route('/login', methods= ['POST'])
def login():
    username= request.form.get('username')
    password= request.form.get('password')
    if not username or not password:
        return jsonify({"message":"missing fields"}), 400
    user= User.query.filter_by(username=username).first()
    if not user:
        return jsonify({"message":"user not exist"}), 400
    if check_password_hash(user.password, password):
        token= create_access_token(identity=str(user.id))
        return jsonify({"message": "login success", "token":token, "username":user.username}), 200
    else:
        return jsonify({"message": "wrong password"}), 500
    

#forget password route
@app.route('/forget-password', methods=["POST"])
def forget_password():
    username= request.form.get('username')
    new_password= request.form.get('password')
    if not username or not new_password:
        return jsonify({"message": "missing fields"}), 400
    user= User.query.filter_by(username=username).first()
    if not user:
        return jsonify({"message": "user not exist"}), 400
    user.password= generate_password_hash(new_password)
    try:
        db.session.commit()
        return jsonify({"message": "password reset successfully"}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({"message":"database is busy"}), 500

#my posts
@app.route('/my-posts')
@jwt_required()
def get_all_posts():
    user_id= int(get_jwt_identity())
    raw_post=Post.query.filter_by(user_id=user_id).all()
    posts=[]
    for post in raw_post:
        posts.append({
            "id":post.id,
            "text": post.text,
            "created_at": post.created_on.isoformat()
        })
    return jsonify({"posts": posts, "message":"success"}), 200

#create post
@app.route('/create-post', methods=["POST"])
@jwt_required()
def create_post():
    data= request.get_json()
    #print(data)
    if not data or not data.get("text"):
        return jsonify({"message": "Invalid data"}), 400
    text= data.get("text")
    user_id = get_jwt_identity()
    if not text or not user_id:
        return jsonify({"message":"missing fields"}), 400
    user= User.query.get(user_id)
    if not user: 
        return jsonify({"message": "user not found"}), 400
    
    new_post= Post(
        text= text,
        user_id= int(user_id)
    )
    try:
        db.session.add(new_post)
        db.session.commit()
        return jsonify({"message": "post created"}), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({"message": "Error creating the post"}), 500

#update post
@app.route('/update-post/<int:post_id>', methods=["PUT"])
@jwt_required()
def update_post(post_id):
    data = request.get_json()
    if not data or not data.get('text'):
        return jsonify({"message": "Missing fields"}), 400
    text= data.get('text')
    user_id= int(get_jwt_identity())
    post = Post.query.get(post_id)
    if not post:
        return jsonify({"message": "Post not found"}), 404
    #print(post.user_id ,user_id)
    if post.user_id != user_id:
        return jsonify({"message": "this is not your post"}), 403
    try:
        post.text = text
        db.session.commit()
        return jsonify({"message": "Post updated"}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({"message": "Error updating the post", "error": str(e)}), 500

#delete post
@app.route('/delete-post/<int:post_id>', methods=["DELETE"])
@jwt_required()
def delete_post(post_id):
    post = Post.query.get(post_id)
    if not post:
        return jsonify({"message": "Post not found"}), 404
    user_id= int(get_jwt_identity())
    if post.user_id != user_id:
        return jsonify({"message":"this is not your post"}), 403
    try:
        db.session.delete(post)
        db.session.commit()
        return jsonify({"message": "Post deleted"}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({"message": "Error deleting the post", "error": str(e)}), 500
    
#view all comments
@app.route('/all-comments/<int:post_id>')
@jwt_required()
def get_all_comments(post_id):
    raw_comments= Comment.query.filter_by(post_id=post_id).all()
    comments=[
        {"id": c.id, "text": c.text, "created_on":c.created_on.isoformat()}
        for c in raw_comments
    ]
    return jsonify({"comments": comments}), 200

#creating comment  
@app.route('/create-comment/<int:post_id>', methods=["POST"])
@jwt_required()
def create_comment(post_id):
    data = request.get_json()
    if not data:
        return jsonify({"message":"Invalid data"}), 400
    user_id= int(get_jwt_identity())
    text= data.get("text")
    if not text or not post_id or not user_id:
        return jsonify({"message": "Missing fields"}), 400
    post = Post.query.get(post_id)
    if not post:
        return jsonify({"message": "page not found"}), 404
    new_comment = Comment(
        text= text,
        post_id= post_id,
        user_id= user_id
    )
    try:
        db.session.add(new_comment)
        db.session.commit()
        return jsonify({"message": "comment created"}), 200
    except Exception as e:
        db.session.rollback()
        return ({"message": "some error occured"}), 500

#deleting the comment
@app.route('/delete-comment/<int:comment_id>', methods=["DELETE"])
@jwt_required()
def delete_comment(comment_id):
    user_id= int(get_jwt_identity())
    comment = Comment.query.get(comment_id)
    if not comment:
        return jsonify({"message": "Comment not found"}), 404

    post = Post.query.get(comment.post_id)
    if not post:
        return jsonify({"message": "Post not found"}), 404

    if comment.user_id != user_id and post.user_id != user_id:
        return jsonify({"message": "Not authorized to delete this comment"}), 403

    try:
        db.session.delete(comment)
        db.session.commit()
        return jsonify({"message": "Comment deleted"}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({"message": "Error deleting comment", "error": str(e)}), 500


if __name__ == "__main__":
    app.run(debug=True)