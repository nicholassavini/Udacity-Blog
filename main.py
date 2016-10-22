#!/usr/bin/env python
import os
import re
import jinja2
import webapp2
import random
from string import letters
import hashlib
import hmac

from google.appengine.ext import ndb
from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                                autoescape=True)

secret = "as;digjh34968qt[asireg"

def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)

def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())

def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val

class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        params['user'] = self.user
        return render_str(template, **params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))

class Post(ndb.Model, Handler):
    post_title = ndb.StringProperty(required=True)
    post_text = ndb.TextProperty(required=True)
    post_created = ndb.DateTimeProperty(auto_now_add=True)
    last_modified = ndb.DateTimeProperty(auto_now=True)
    created_by = ndb.StringProperty(required=True)
    likes = ndb.StringProperty(repeated=True)

    def render_post(self):
        self._render_text = self.post_text.replace('\n', '<br>')
        return render_str("post.html", p=self)


#### Blog Presentation

class Blog(Handler):

    def get(self):
        posts = Post.query().order(-Post.post_created)
        self.render("front.html", posts=posts, username=self.user)


class AddPost(Handler):
    def get(self):
        if self.user:
            self.render("newpost.html")
        else:
            self.redirect("/login")

    def post(self):
        if self.user:
                post_title = self.request.get("post_title")
                post_text = self.request.get("post_text")
                created_by = self.user.name
                # see about params
                if post_title and post_text:
                    p = Post(post_title=post_title, post_text=post_text,
                             created_by=created_by)
                    p.put()

                    self.redirect("/%s" % str(p.key.id()))
                else:
                    error = "We need both a post title and a post body!"
                    self.render("newpost.html", post_title=post_title, post_text=post_text, error=error)
        else:
            self.redirect("/login")

def get_post(post_id):
        post = ndb.Key('Post', int(post_id)).get()
        return post

def get_comments(post_id):
        comments = Comment.query(Comment.post_id == post_id).order(Comment.comment_date)
        return comments

class Permalink(Handler):
    def get(self, post_id):
        post = get_post(post_id)
        comments = get_comments(post_id)
        if not post:
            self.error(404)
            return

        self.render("permalink.html", p=post, comments=comments)

class EditPost(Handler):
    def get(self, post_id):
        post = get_post(post_id)
        if post.created_by == self.user.name:
            self.render('editpost.html', post=post)
        else:
            error = "Only the user who created this post can modify it."
            self.render("error.html", error=error)

    def post(self, post_id):
        if self.user:
                post = get_post(post_id)
                post.post_title = self.request.get("post_title")
                post.post_text = self.request.get("post_text")
                post.put()

                self.redirect("/%s" % str(post_id))
        else:
            self.redirect("/login")

class DeletePost(Handler):
    def get(self, post_id):
        post = get_post(post_id)
        if post.created_by == self.user.name:
            ndb.Key('Post', int(post_id)).delete()
            self.render("delete.html")
        else:
            error = "Only the user who created this post can modify it."
            self.render("error.html", error=error)

class LikePost(Handler):
    def post(self, post_id):
        if self.user:
            post = get_post(post_id)
            likes = [x.encode("utf-8") for x in post.likes]
            username = self.user.name
            if username in likes or username == post.created_by:
                self.redirect("/")
            else:
                post.likes.append(username)
                post.put()
                self.redirect("/")
        else:
            self.redirect("/login")

class UnlikePost(Handler):
    def post(self, post_id):
        post = get_post(post_id)
        likes = [x.encode("utf-8") for x in post.likes]
        likes.remove(self.user.name)
        post.likes = likes
        post.put()
        self.redirect("/")

#### User Code

def make_salt(length = 5):
    return ''.join(random.choice(letters) for x in xrange(length))

def make_pw_hash(name, pw, salt = None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, h)

def valid_pw(name, password, h):
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)

def users_key(group = 'default'):
    return db.Key.from_path('users', group)

class User(db.Model):
    name = db.StringProperty(required=True)
    pw_hash = db.StringProperty(required=True)
    email = db.StringProperty()

    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid, parent=users_key())

    @classmethod
    def by_name(cls, name):
        u = User.all().filter('name =', name).get()
        return u

    @classmethod
    def register(cls, name, pw, email=None):
        pw_hash = make_pw_hash(name, pw)
        return User(parent=users_key(),
                    name=name,
                    pw_hash=pw_hash,
                    email=email)

    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
PASS_RE = re.compile(r"^.{3,20}$")
EMAIL_RE = re.compile(r"^[\S]+@[\S]+.[\S]+$")

def valid_username(username):
    return USER_RE.match(username)

def valid_password(password):
    return PASS_RE.match(password)

def valid_email(email):
    return EMAIL_RE.match(email)

class Signup(Handler):

    def get(self):
        self.render("signup.html")

    def post(self):
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')

        # consider moving the has-error part to a js script
        has_error = False
        params = dict(username=self.username, email=self.email,
            password=self.password, verify=self.verify)

        if not valid_username(self.username):
            params['username_error'] = "Not a valid username"
            params['user_class'] = "has-error"
            has_error = True
        if not valid_password(self.password):
            params['password_error'] = "Not a valid password"
            params['pass_class'] = "has-error"
            has_error = True
        elif self.password != self.verify:
            params['verify_error'] = "Passwords do not match"
            params['ver_class'] = "has-error"
            has_error = True
        if not valid_email(self.email):
            params['email_error'] = "Not a valid email"
            params['email_class'] = "has-error"
            has_error = True
        if has_error:
            self.render("signup.html", **params)
        else:
            self.done(params)


class Register(Signup):
    def done(self, params):
        u = User.by_name(self.username)
        if u:
            params['username_error'] = "That user already exists."
            params['user_class'] = "has-error"
            self.render('signup.html', **params)
        else:
            u = User.register(self.username, self.password, self.email)
            u.put()

            self.login(u)
            self.redirect('/')

class Login(Handler):
    def get(self):
        self.render('login.html')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        u = User.login(username, password)
        if u:
            self.login(u)
            self.redirect('/')
        else:
            msg = 'Invalid login'
            self.render('login.html', error=msg)

class Logout(Handler):
    def get(self):
        self.logout()
        self.redirect('/')

#### Comment Stuff

class Comment(ndb.Model):
    username = ndb.StringProperty(required=True)
    comment_title = ndb.StringProperty(required=True)
    comment_text = ndb.TextProperty(required=True)
    post_id = ndb.StringProperty(required=True)
    comment_date = ndb.DateTimeProperty(auto_now_add=True)

class AddComment(Handler):
    def post(self, post_id):
        if self.user:
            username = self.user.name
            comment_title = self.request.get("comment_title")
            comment_text = self.request.get("comment_text")
            post_id = post_id

            if comment_title and comment_text:
                c = Comment(username=username, comment_title=comment_title,
                            comment_text=comment_text, post_id=post_id)
                c.put()
                self.redirect("/%s" % str(post_id))
            else:
                error = "Can't post blank comment!"
                #self.render(".html", post_title=post_title, post_text=post_text, error=error)
        else:
            self.redirect("/login")

# make sure to create redirect success page
class Welcome(Handler):
    def get(self):
        if self.user:
            self.render('welcome.html', username=self.user.name)
        else:
            self.redirect('/signup')

app = webapp2.WSGIApplication([('/', Blog),
                               ('/newpost', AddPost),
                               ('/([0-9]+)', Permalink),
                               ('/([0-9]+)/edit', EditPost),
                               ('/([0-9]+)/delete', DeletePost),
                               ('/([0-9]+)/like', LikePost),
                               ('/([0-9]+)/unlike', UnlikePost),
                               ('/([0-9]+)/addcomment', AddComment),
                               ('/signup', Register),
                               ('/login', Login),
                               ('/welcome', Welcome),
                               ('/logout', Logout)
                              ],
                              debug=True)
