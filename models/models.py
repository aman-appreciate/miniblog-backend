from extensions import db
from datetime import datetime

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
    image_url= db.Column(db.String(500), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable= False)
    likes = db.Column(db.Integer, default=0)
    noofcomments= db.Column(db.Integer, default=0)
    created_on = db.Column(db.DateTime, default= datetime.utcnow)
    comments = db.relationship("Comment", backref='post', lazy=True)
#comment model
class Comment(db.Model):
    id = db.Column(db.Integer, primary_key= True)
    text= db.Column(db.Text, nullable = False)
    created_on = db.Column(db.DateTime, default= datetime.utcnow)
    post_id = db.Column(db.Integer, db.ForeignKey("post.id"), nullable= False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable= False)
