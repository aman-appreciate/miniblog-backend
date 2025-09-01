from flask import Flask, jsonify
from datetime import timedelta
from dotenv import load_dotenv
import os
import cloudinary
from extensions import db, jwt
from routes.auth_routes import auth_bp
from routes.post_routes import post_bp
from routes.comment_routes import comment_bp

load_dotenv()

app= Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI']= os.getenv('DATABASE_URI')
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY')
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(minutes=60)

db.init_app(app)
jwt.init_app(app)

cloudinary.config(
    cloud_name=os.getenv("CLOUDINARY_CLOUD_NAME"),
    api_key= os.getenv("CLOUDINARY_API_KEY"),
    api_secret= os.getenv("CLOUDINARY_API_SECRET"),
    secure=True
)

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

@app.route("/")
def home():
    return jsonify({"message": "Server is running"}), 200

app.register_blueprint(auth_bp, url_prefix="/auth")
app.register_blueprint(post_bp, url_prefix="/post")
app.register_blueprint(comment_bp, url_prefix="/comment")

with app.app_context():
    db.create_all()

if __name__ == "__main__":
    app.run(debug=True)