from extensions import db
from flask import request, jsonify, Blueprint
from models.models import User
from werkzeug.security import generate_password_hash, check_password_hash
from flask_jwt_extended import create_access_token

auth_bp= Blueprint("auth", __name__)

#home route
@auth_bp.route('/', methods= ['GET'])
def home():
    return "this is auth", 200

#register route
@auth_bp.route('/register', methods= ['POST'])
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
@auth_bp.route('/login', methods= ['POST'])
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
@auth_bp.route('/forget-password', methods=["POST"])
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
