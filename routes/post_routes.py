from flask import jsonify, request, Blueprint
import cloudinary
import cloudinary.uploader
from extensions import db
from flask_jwt_extended import get_jwt_identity, jwt_required
from models.models import Post, User

post_bp= Blueprint("/post", __name__)

@post_bp.route('/', methods= ['GET'])
def home():
    return "this is post", 200
@post_bp.route('/my-posts')
@jwt_required()
def get_all_posts():
    user_id= int(get_jwt_identity())
    raw_post=Post.query.filter_by(user_id=user_id).all()
    posts=[]
    for post in raw_post:
        posts.append({
            "id":post.id,
            "text": post.text,
            "image_url": post.image_url,
            "created_at": post.created_on.isoformat(),
            "likes": post.likes,
            "noofcomments": post.noofcomments
        })
    return jsonify({"posts": posts, "message":"success"}), 200

#create post
@post_bp.route('/create-post', methods=["POST"])
@jwt_required()
def create_post():
    try:
        text = request.form.get("text")
        image = request.files.get("image")
        user_id = get_jwt_identity()

        if not text or not user_id:
            return jsonify({"message": "Missing required fields"}), 400

        user = User.query.get(user_id)
        if not user:
            return jsonify({"message": "User not found"}), 404

        image_url = None
        if image:
            upload_result = cloudinary.uploader.upload(image)
            image_url = upload_result.get("secure_url")

        new_post = Post(
            text=text,
            user_id=int(user_id),
            image_url=image_url 
        )

        db.session.add(new_post)
        db.session.commit()

        return jsonify({
            "message": "Post created successfully",
            "post": {
                "id": new_post.id,
                "text": new_post.text,
                "user_id": new_post.user_id,
                "image_url": new_post.image_url
            }
        }), 201

    except Exception as e:
        db.session.rollback()
        print("Error creating post:", e)
        return jsonify({"message": "Error creating the post"}), 500

#update post
@post_bp.route('/update-post/<int:post_id>', methods=["PUT"])
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
@post_bp.route('/delete-post/<int:post_id>', methods=["DELETE"])
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
