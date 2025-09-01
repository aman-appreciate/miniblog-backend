from flask import jsonify, request, Blueprint
from flask_jwt_extended import jwt_required, get_jwt_identity

from extensions import db
from models.models import Comment, Post


comment_bp = Blueprint("comment", __name__)

@comment_bp.route('/', methods= ['GET'])
def home():
    return "this is comment", 200

#view all comments
@comment_bp.route('/all-comments/<int:post_id>')
@jwt_required()
def get_all_comments(post_id):
    raw_comments= Comment.query.filter_by(post_id=post_id).all()
    comments=[
        {"id": c.id, "text": c.text, "created_on":c.created_on.isoformat()}
        for c in raw_comments
    ]
    return jsonify({"comments": comments}), 200

#creating comment  
@comment_bp.route('/create-comment/<int:post_id>', methods=["POST"])
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
@comment_bp.route('/delete-comment/<int:comment_id>', methods=["DELETE"])
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
