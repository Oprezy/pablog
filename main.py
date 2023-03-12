from flask import Flask, render_template, redirect, url_for, flash, request
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import ForeignKey
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm, RegisterForm, LoginForm, CreateComment
from flask_gravatar import Gravatar
from functools import wraps
import os


def admin_only(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if current_user.id == 1:
            return func(*args, **kwargs)
        else:
            return redirect(url_for('get_all_posts'))
    return wrapper

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get("SECRET_KEY")
ckeditor = CKEditor(app)
Bootstrap(app)

##CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("DATABASE_URL", "sqlite:///realblog.db")
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


##CONFIGURE TABLES


class Comments(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, ForeignKey('users.id'))
    user = db.relationship('User', back_populates='comments')
    post_id = db.Column(db.Integer, ForeignKey('blog_posts.id'))
    post = db.relationship('BlogPost', back_populates='blog_comments')
    text = db.Column(db.String(1000), nullable=False)


class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    author_id = db.Column(db.Integer, ForeignKey('users.id'))
    author = db.relationship('User', back_populates="posts")
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
    blog_comments = db.relationship('Comments', back_populates='post', foreign_keys=[Comments.post_id])
    

class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(250), nullable=False, unique=True)
    name = db.Column(db.String(250), nullable=False)
    password = db.Column(db.String(250), nullable=False)
    posts = db.relationship('BlogPost', back_populates='author', foreign_keys=[BlogPost.author_id])
    comments = db.relationship('Comments', back_populates='user', foreign_keys=[Comments.user_id])
    def logged_in():
        return current_user.is_authenticated

login_manager = LoginManager()
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def get_all_posts():
    db.create_all()
    #print("hello")
    # new_user = User(email = 'prezzy1@blog.com', name = 'Prezzy1', password = 'jhgfds')        
    # new_post = BlogPost(author=current_user, title='Writer', subtitle='Founder', date='28th', body='Again, Obi will be president', img_url='https://cdn.vanguardngr.com/wp-content/uploads/2022/10/Peter-Obi-1.webp')
    # db.session.add(new_user)
    # db.session.add(new_post) error ooo
    # db.session.commit()
    posts = BlogPost.query.all()
    return render_template("index.html", all_posts=posts)


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        check_user = User.query.filter_by(email=form.email.data).first()
        if not check_user:
            new_user = User(
                email = form.email.data,
                name = form.name.data,
                password = generate_password_hash(form.password.data, method="pbkdf2:sha256", salt_length=8)
            )
            db.session.add(new_user)
            db.session.commit()
        else:
            flash(f"Your email {form.email.data} already exist. Use it to login")
            return redirect(url_for('login'))
        user = User.query.filter_by(email=form.email.data).first()
        login_user(user)
        return redirect(url_for('get_all_posts'))

    return render_template("register.html", form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and check_password_hash(user.password, form.password.data):
            login_user(user)
            flash('Logged in successfully')
            return redirect(url_for('get_all_posts'))
        elif not user:
            flash('Email does not exist')
        else:
            flash('Your password is wrong')
    return render_template("login.html", form=form)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:apost_id>", methods=['GET', 'POST'])
def show_post(apost_id):
    # Post phase 
    requested_post = BlogPost.query.get(apost_id)

    # Create Comment phase
    form = CreateComment()
    if form.validate_on_submit():
        new_comment = Comments(
            text=form.text.data, 
            user=current_user,
            post_id=apost_id
        )
        db.session.add(new_comment)
        db.session.commit()
        form.text.data = ""

    # View comment phase
    comments = Comments.query.filter_by(post_id=apost_id)
    return render_template("post.html", post=requested_post, form=form, comments=comments)


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")

@app.route("/new-post", methods=['GET', 'POST'])
@admin_only
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        # new_post = BlogPost(author='prezzy', title='anyone', subtitle='daada', date='3849', body='bdjdiosos', img_url='kjhgf')

        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=current_user,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form)

@app.route("/comment", methods=['POST'])
def comment():
    form = CreateComment()
    if form.validate_on_submit():
        new_comment = Comments(
            text=form.text.data, 
            user=current_user
        )
        db.session.add(new_comment)
        db.session.commit()

@app.route("/edit-post/<int:post_id>")
@admin_only
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.author = edit_form.author.data
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form)


@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))

@app.route('/test')
def test():
    # this is a testing environment
    comments = Comments.query.all()
    for comment in comments:
        print(comment.text)
        print("hi")
    return render_template('test.html')


if __name__ == "__main__":
    
    app.run(debug=True)
    db.create_all()


# post = Post.query.first()
# user = post.user


