#!/usr/bin/env python
import os
import re
import random
from string import letters
import hashlib
import hmac
import webapp2
import jinja2
from google.appengine.ext import ndb

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
    """ Doc """
    def write(self, *a, **kw):
        """ Doc """
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        """ Doc """
        params['user'] = self.user
        return render_str(template, **params)

    def render(self, template, **kw):
        """ Doc """
        self.write(self.render_str(template, **kw))

    def set_secure_cookie(self, name, val):
        """ Doc """
        cookie_val = make_secure_val(val)
        self.response.headers.add_header('Set-Cookie',
                                         '%s=%s; Path=/' % (name, cookie_val))

    def read_secure_cookie(self, name):
        """ Doc """
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def login(self, user):
        """ Doc """
        self.set_secure_cookie('user_id', str(user.key.id()))

    def logout(self):
        """ Doc """
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    def initialize(self, *a, **kw):
        """ Doc """
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))


class Post(ndb.Model):
    """ Doc """
    post_title = ndb.StringProperty(required=True)
    post_text = ndb.TextProperty(required=True)
    post_created = ndb.DateTimeProperty(auto_now_add=True)
    last_modified = ndb.DateTimeProperty(auto_now=True)
    created_by = ndb.StringProperty(required=True)
    likes = ndb.StringProperty(repeated=True)

    def render_post(self):
        """ Doc """
        self._render_text = self.post_text.replace('\n', '<br>')
        return render_str("post.html", p=self)


# Blog Presentation

class Blog(Handler):
    """ Doc """
    def get(self):
        """ Doc """
        posts = Post.query().order(-Post.post_created)
        self.render("front.html", posts=posts, username=self.user)


class AddPost(Handler):
    """ Doc """
    def get(self):
        """ Doc """
        if self.user:
            self.render("new_post.html")
        else:
            self.redirect("/login")

    def post(self):
        """ Doc """
        if self.user:
            post_title = self.request.get("post_title")
            post_text = self.request.get("post_text")
            created_by = self.user.name

            params = dict(post_title=post_title, post_text=post_text)
            has_error = False
            if not post_title:
                params['title_class'] = "has-error"
                params['title_error'] = "We need a post title!"
                has_error = True
            if not post_text:
                params['text_class'] = "has-error"
                params['text_error'] = "We need a post body!"
                has_error = True

            if has_error:
                self.render("new_post.html", **params)
            else:
                p = Post(post_title=post_title, post_text=post_text,
                         created_by=created_by)
                p.put()

                self.redirect("/%s" % str(p.key.id()))
        else:
            self.redirect("/login")


def get_item(item_type, item_id):
    post = ndb.Key(item_type, int(item_id)).get()
    return post


# consider splitting this into two functions for reusability
def get_comments(post_id):
    comments = Comment.query(Comment.post_id == post_id)
    comments = comments.order(Comment.comment_date)
    return comments


class Permalink(Handler):
    """ Doc """
    def get(self, post_id):
        """ Doc """
        post = get_item('Post', post_id)
        comments = get_comments(post_id)
        if not post:
            self.error(404)
            return

        self.render("permalink.html", p=post, comments=comments)


class EditPost(Handler):
    """ Doc """
    def get(self, post_id):
        """ Doc """
        if self.user:
            post = get_item('Post', post_id)
            if post.created_by == self.user.name:
                self.render('edit_post.html', p=post)
            else:
                error = "Only the user who created this post can modify it."

                self.render("error.html", error=error)
        else:
            self.redirect("/login")

    def post(self, post_id):
        """ Doc """
        post = get_item('Post', post_id)
        if post.created_by == self.user.name:
            if self.request.get("action") == "edit":
                post_title = self.request.get("post_title")
                post_text = self.request.get("post_text")

                params = dict(p=post)
                has_error = False

                if not post_title:
                    params['title_class'] = "has-error"
                    params['title_error'] = "We need a post title!"
                    has_error = True
                if not post_text:
                    params['text_class'] = "has-error"
                    params['text_error'] = "We need a post body!"
                    has_error = True

                if has_error:
                    self.render("edit_post.html", **params)
                else:
                    post.post_title = post_title
                    post.post_text = post_text
                    post.put()

                    self.redirect("/%s" % str(post_id))
            elif self.request.get("action") == "delete":
                ndb.Key('Post', int(post_id)).delete()
                comments = Comment.query(Comment.post_id == post_id)
                keys = comments.fetch(keys_only=True)
                ndb.delete_multi(keys)

                self.redirect("/")
        else:
            error = "Only the user who created this post can modify it."

            self.render("error.html", error=error)


class LikePost(Handler):
    """ Doc """
    def post(self, post_id):
        """ Doc """
        if self.user:
            post = get_item('Post', post_id)
            likes = [l.encode("utf-8") for l in post.likes]
            username = self.user.name
            if username in likes or username == post.created_by:
                self.redirect("/%s" % str(post.key.id()))
            else:
                post.likes.append(username)
                post.put()

                self.redirect("/")
        else:
            self.redirect("/login")


class UnlikePost(Handler):
    def post(self, post_id):
        if self.user:
            post = get_item('Post', post_id)
            likes = [l.encode("utf-8") for l in post.likes]
            likes.remove(self.user.name)

            post.likes = likes
            post.put()

            self.redirect("/%s" % str(post.key.id()))
        else:
            self.redirect("/login")

#### User Code


def make_salt(length=5):
    return ''.join(random.choice(letters) for x in xrange(length))


def make_pw_hash(name, pw, salt=None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, h)


def valid_pw(name, password, h):
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)


class User(ndb.Model):
    name = ndb.StringProperty(required=True)
    pw_hash = ndb.StringProperty(required=True)
    email = ndb.StringProperty()

    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid)

    @classmethod
    def by_name(cls, name):
        u = User.query(User.name == name).get()
        return u

    @classmethod
    def register(cls, name, pw, email=None):
        pw_hash = make_pw_hash(name, pw)
        return User(name=name, pw_hash=pw_hash, email=email)

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
            self.redirect('/welcome')
        else:
            error = 'Invalid login'
            self.render('login.html', error=error)


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
    likes = ndb.StringProperty(repeated=True)

    def render_comments(self):
        """ Doc """
        self._render_text = self.comment_text.replace('\n', '<br>')
        return render_str("comment.html", c=self)


# These are probably supposed to support HTML
class AddComment(Handler):
    def post(self, post_id):
        if self.user:
            username = self.user.name
            comment_title = self.request.get("comment_title")
            comment_text = self.request.get("comment_text")

            params = dict(comment_title=comment_title,
                          comment_text=comment_text)
            has_error = False
            if not comment_title:
                params['title_class'] = "has-error"
                params['title_error'] = "We need a comment title!"
                has_error = True
            if not comment_text:
                params['text_class'] = "has-error"
                params['text_error'] = "We need a comment body!"
                has_error = True

            if has_error:
                params['post_id'] = post_id
                self.render("new_comment.html", **params)

            else:
                c = Comment(username=username, comment_title=comment_title,
                            comment_text=comment_text, post_id=post_id)
                c.put()

                self.redirect("/%s" % str(post_id))
        else:
            self.redirect("/login")


class EditComment(Handler):
    def get(self, post_id, comment_id):
        if self.user:

            comment = get_item('Comment', comment_id)
            post = get_item('Post', post_id)
            if comment.username == self.user.name:
                self.render('edit_comment.html', c=comment, p=post)
            else:
                error = "Only the user who created this comment can modify it."
                self.render("error.html", error=error)
        else:
            self.redirect("/login")

    def post(self, post_id, comment_id):
        comment = get_item('Comment', comment_id)
        if comment.username == self.user.name:
            if self.request.get("action") == "edit":
                comment_title = self.request.get("comment_title")
                comment_text = self.request.get("comment_text")

                params = dict(comment_title=comment_title,
                              comment_text=comment_text, c=comment)
                has_error = False
                if not comment_title:
                    params['title_class'] = "has-error"
                    params['title_error'] = "We need a comment title!"
                    has_error = True
                if not comment_text:
                    params['text_class'] = "has-error"
                    params['text_error'] = "We need a comment body!"
                    has_error = True

                if has_error:
                    params['post_id'] = post_id
                    self.render("edit_comment.html", **params)
                else:
                    comment.comment_title = self.request.get("comment_title")
                    comment.comment_text = self.request.get("comment_text")
                    comment.put()

                    self.redirect("/%s" % str(post_id))
            elif self.request.get("action") == "delete":
                ndb.Key('Comment', int(comment_id)).delete()

                self.redirect("/%s" % str(post_id))
        else:
            error = "Only the user who created this comment can modify it."
            self.render("error.html", error=error)


class LikeComment(Handler):
    def post(self, post_id, comment_id):
        if self.user:
            comment = get_item('Comment', comment_id)
            likes = [u.encode("utf-8") for u in comment.likes]
            username = self.user.name
            if username in likes or username == comment.username:
                self.redirect("/%s" % str(post_id))
            else:
                comment.likes.append(username)
                comment.put()
                self.redirect("/%s" % str(post_id))
        else:
            self.redirect("/login")


class UnlikeComment(Handler):
    def post(self, post_id, comment_id):
        if self.user:
            comment = get_item('Comment', comment_id)
            likes = [u.encode("utf-8") for u in comment.likes]
            username = self.user.name
            if username in likes or username == comment.username:
                likes.remove(username)
                comment.likes = likes
                comment.put()
                self.redirect("/%s" % str(post_id))
            else:
                self.redirect("/%s" % str(post_id))
        else:
            self.redirect("/login")


class Welcome(Handler):
    def get(self):
        if self.user:
            self.render('welcome.html', username=self.user.name)
        else:
            self.redirect('/login')

app = webapp2.WSGIApplication([('/', Blog),
                               ('/new_post', AddPost),
                               ('/([0-9]+)', Permalink),
                               ('/([0-9]+)/edit', EditPost),
                               ('/([0-9]+)/like', LikePost),
                               ('/([0-9]+)/unlike', UnlikePost),
                               ('/([0-9]+)/add_comment', AddComment),
                               ('/([0-9]+)/([0-9]+)/edit', EditComment),
                               ('/([0-9]+)/([0-9]+)/like', LikeComment),
                               ('/([0-9]+)/([0-9]+)/unlike', UnlikeComment),
                               ('/signup', Register),
                               ('/login', Login),
                               ('/welcome', Welcome),
                               ('/logout', Logout)],
                              debug=True)
