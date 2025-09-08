from flask import jsonify, request, Blueprint
import cloudinary
import cloudinary.uploader
from extensions import db
from flask_jwt_extended import get_jwt_identity, jwt_required
from models.models import Post, User, PostLike

post_bp= Blueprint("/post", __name__)

@post_bp.route('/', methods= ['GET'])
def home():
    return "this is post", 200


@post_bp.route('/my-posts')
@jwt_required()
def get_all_posts():
    user_id= int(get_jwt_identity())
    raw_posts = Post.query.order_by(Post.created_on.desc()).all()
    posts=[]
    for post in raw_posts:
        is_liked = PostLike.query.filter_by(user_id=user_id, post_id=post.id).first() is not None
        posts.append({
            "id":post.id,
            "text": post.text,
            "image_url": post.image_url,
            "created_at": post.created_on.isoformat(),
            "likes": post.likes,
            "noofcomments": post.noofcomments,
            "username": post.author.username,
            "isLiked": is_liked
        })
    return jsonify({"posts": posts, "message":"success"}), 200

@post_bp.route('/<int:post_id>', methods=["GET"])
@jwt_required()
def get_post(post_id):
    user_id = int(get_jwt_identity())
    post = Post.query.get(post_id)

    if not post:
        return jsonify({"message": "Post not found"}), 404

    return jsonify({
        "id": post.id,     
        "text": post.text,
        "image": post.image_url,
    }), 200


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
                "image_url": new_post.image_url,
                
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
    user_id = int(get_jwt_identity())
    post = Post.query.get(post_id)

    if not post:
        return jsonify({"message": "Post not found"}), 404

    if post.user_id != user_id:
        return jsonify({"message": "This is not your post"}), 403

    try:
        text = request.form.get("text")
        if not text:
            return jsonify({"message": "Text is required"}), 400
        post.text = text

        if request.form.get("remove_image") == "true":
            post.image_url = None

        if "image" in request.files:
            image_file = request.files["image"]
            if image_file:
                upload_result = cloudinary.uploader.upload(image_file)
                post.image_url = upload_result["secure_url"]

        db.session.commit()
        return jsonify({"message": "Post updated successfully"}), 200

    except Exception as e:
        db.session.rollback()
        return jsonify({
            "message": "Error updating the post",
            "error": str(e)
        }), 500

#delete post
@post_bp.route('/delete-post/<int:post_id>', methods=["DELETE"])
@jwt_required()
def delete_post(post_id):
    post = Post.query.get(post_id)
    print(post_id, post)
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
        print(e)
        db.session.rollback()
        return jsonify({"message": "Error deleting the post", "error": str(e)}), 500


@post_bp.route('/like', methods=["POST"])
@jwt_required()
def like_post():
    print("hell")
    data = request.get_json()
    post_id = data.get("post_id")
    action = data.get("action") 
    user_id = int(get_jwt_identity())
    print(data)

    if post_id is None or action is None:
        return jsonify({"message": "Missing post_id or action"}), 200

    post = Post.query.get(post_id)
    if not post:
        return jsonify({"message": "Post not found"}), 404

    if action == 1:
        existing = PostLike.query.filter_by(user_id=user_id, post_id=post_id).first()
        if not existing:
            new_like = PostLike(user_id=user_id, post_id=post_id)
            db.session.add(new_like)
            post.likes += 1

    elif action == 0:
        existing = PostLike.query.filter_by(user_id=user_id, post_id=post_id).first()
        if existing:
            db.session.delete(existing)
            if post.likes > 0:
                post.likes -= 1

    db.session.commit()

    return jsonify({
        "message": "success",
        "post_id": post.id,
        "likes": post.likes
    }), 200
