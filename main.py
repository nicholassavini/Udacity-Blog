#!/usr/bin/env python
import os
import re
import random
import webapp2
import hashlib
import hmac
from string import letters

import jinja2

from google.appengine.ext import ndb

# Jinja Configuration
template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                               autoescape=True)


# Global Variables

secret = "as;digjh34968qt[asireg"

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
PASS_RE = re.compile(r"^.{3,20}$")
EMAIL_RE = re.compile(r"^[\S]+@[\S]+.[\S]+$")


# Global Functions

def render_str(template, **params):
    """ Prints the given template with the given parameters """
    t = jinja_env.get_template(template)
    return t.render(params)


def make_secure_val(val):
    """ Takes a string and encodes it with the given secret """
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())


def check_secure_val(secure_val):
    """ checks to makes sure that the given value has been properly encoded """
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val


def get_item(item_type, item_id):
    """
    Given the database type, and the id of the entity in question, returns
    the key for that entity
    """
    key = ndb.Key(item_type, int(item_id))
    item = key.get()
    return item


def get_comments(post_id):
    """ A simple query to get the comments for a given post """
    comments = Comment.query(Comment.post_id == post_id)
    comments = comments.order(Comment.comment_date)
    return comments


def make_salt(length=5):
    """ Creates a random salt """
    return ''.join(random.choice(letters) for x in xrange(length))


def make_pw_hash(name, pw, salt=None):
    """ Hashes a password with the salt created above """
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, h)


def valid_pw(name, password, h):
    """ Makes sure that provided password matches the one for that user """
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)


def valid_username(username):
    """ Checks to see if the provided username fits the given criteria """
    return USER_RE.match(username)


def valid_password(password):
    """ Checks to see if the provided password fits the given criteria """
    return PASS_RE.match(password)


def valid_email(email):
    """ Checks to see if the provided email fits the given criteria """
    return EMAIL_RE.match(email)


# Data Models
class Post(ndb.Model):
    """
    Creates an instance of the class that allows for the creation of new blog
    posts that may be stored as entities
    """
    post_title = ndb.StringProperty(required=True)
    post_text = ndb.TextProperty(required=True)
    post_created = ndb.DateTimeProperty(auto_now_add=True)
    last_modified = ndb.DateTimeProperty(auto_now=True)
    created_by = ndb.StringProperty(required=True)
    likes = ndb.StringProperty(repeated=True)

    def render_post(self):
        """
        Replaces carriage returns in posts so that they can be rendered
        correctly
        """
        self._render_text = self.post_text.replace('\n', '<br>')
        return render_str("post.html", p=self)


class User(ndb.Model):
    """
    Creates an instance of the class that allows for the creation of new users
    that may be stored as entities
    """
    name = ndb.StringProperty(required=True)
    pw_hash = ndb.StringProperty(required=True)
    email = ndb.StringProperty()

    @classmethod
    def by_id(cls, uid):
        """ Retrieves a user by id """
        return User.get_by_id(uid)

    @classmethod
    def by_name(cls, name):
        """ Retrieves a user by username """
        u = User.query(User.name == name).get()
        return u

    @classmethod
    def register(cls, name, pw, email=None):
        """ Creates a new user """
        pw_hash = make_pw_hash(name, pw)
        return User(name=name, pw_hash=pw_hash, email=email)

    @classmethod
    def login(cls, name, pw):
        """ Checks the credentials of a user to allow them to login """
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u


class Comment(ndb.Model):
    """
    Creates an instance of the class that allows for the creation of new
    comments that may be stored as entities
    """
    username = ndb.StringProperty(required=True)
    comment_title = ndb.StringProperty(required=True)
    comment_text = ndb.TextProperty(required=True)
    post_id = ndb.StringProperty(required=True)
    comment_date = ndb.DateTimeProperty(auto_now_add=True)
    likes = ndb.StringProperty(repeated=True)

    def render_comments(self):
        """
        Replaces carriage returns in comments so that they can be rendered
        correctly
        """
        self._render_text = self.comment_text.replace('\n', '<br>')
        return render_str("comment.html", c=self)


class Handler(webapp2.RequestHandler):
    """ The main handler for the blog, responsible for rendering content """
    def write(self, *a, **kw):
        """ Displays the functions with its respective arguments """
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        """
        Passes the template to the Global render_str function and
        and passes user info to the template
        """
        params['user'] = self.user
        return render_str(template, **params)

    def render(self, template, **kw):
        """ Calls render_str to write the template """
        self.write(self.render_str(template, **kw))

    def set_secure_cookie(self, name, val):
        """ Sets a cookie after the value is made secure """
        cookie_val = make_secure_val(val)
        self.response.headers.add_header('Set-Cookie',
                                         '%s=%s; Path=/' % (name, cookie_val))

    def read_secure_cookie(self, name):
        """ Reads the cookie value if one is set """
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def login(self, user):
        """
        Calls the set_secure_cookie function so that the user can remain
        logged in throughout the site
        """
        self.set_secure_cookie('user_id', str(user.key.id()))

    def logout(self):
        """ Removes the cookie for the currently logged in user """
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    def initialize(self, *a, **kw):
        """
        Calls the read_secure_cookie function so that the user can be
        identified throughout the site
        """
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))


# Basic Blog Handlers

class Blog(Handler):
    """ Handles the front of the Blog """
    def get(self):
        """ Generates the front page of the blog """
        posts = Post.query().order(-Post.post_created)
        self.render("front.html", posts=posts, username=self.user)


def user_required(func):
    """ makes sure that the user is logged in """
    def check_user(self, *args, **kwargs):
        """ makes sure that the user is logged in """
        if self.user:
            return func(self, *args, **kwargs)
        else:
            self.redirect("/login")
    return check_user


class AddPost(Handler):
    """ Allows for the addition of a new post """
    @user_required
    def get(self):
        """ Renders the new post page if the user is logged in """
        self.render("new_post.html")

    @user_required
    def post(self):
        """
        Creates a new post if the user is logged in, and the provided values
        are all valid
        """
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


class Permalink(Handler):
    """ Allows for each post to have a permalink page """

    def get(self, post_id):
        """
        Gets the post and all its associated comments and then renders the
        page
        """
        post = get_item('Post', post_id)
        comments = get_comments(post_id)
        if not post:
            self.error(404)
            self.render("404.html")
            return

        self.render("permalink.html", p=post, comments=comments)


class EditPost(Handler):
    """ Allows for a post to be edited """
    @user_required
    def get(self, post_id):
        """
        Renders the edit post template with the values of the post filled in
        if the logged in user is the user who created the post
        """
        post = get_item('Post', post_id)
        if not post:
            self.error(404)
            self.render("404.html")
            return

        if post.created_by == self.user.name:
            self.render('edit_post.html', p=post)
        else:
            error = "Only the user who created this post can modify it."
            self.render("error.html", error=error)

    @user_required
    def post(self, post_id):
        """
        Submits the changes to the post, or deletes the post if the logged in
        user is the user who created the post
        """
        post = get_item('Post', post_id)
        if not post:
            self.error(404)
            self.render("404.html")
            return

        if post.created_by == self.user.name:
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
        else:
            error = "Only the user who created this post can modify it."

            self.render("error.html", error=error)

class DeletePost(Handler):
    """ Allows for a post and its associated comments to be deleted """
    @user_required
    def post(self, post_id):
        """ Runs the post request to delete and post """
        post = get_item('Post', post_id)
        if not post:
            self.error(404)
            self.render("404.html")
            return

        if post.created_by == self.user.name:
            ndb.Key('Post', int(post_id)).delete()
            # Deletes the commments associated with the given post
            comments = Comment.query(Comment.post_id == post_id)
            keys = comments.fetch(keys_only=True)
            ndb.delete_multi(keys)
            self.redirect("/")
        else:
            error = "Only the user who created this post can modify it."
            self.render("error.html", error=error)

class LikePost(Handler):
    """ Allows a post to be liked """
    @user_required
    def post(self, post_id):
        """
        If the user didn't created the post or already liked the post, adds a
        new like the post
        """
        post = get_item('Post', post_id)
        if not post:
            self.error(404)
            self.render("404.html")
            return

        likes = [l.encode("utf-8") for l in post.likes]
        username = self.user.name
        if username in likes or username == post.created_by:
            self.redirect("/%s" % str(post.key.id()))
        else:
            post.likes.append(username)
            post.put()
            self.redirect("/")


class UnlikePost(Handler):
    """ Allows a post to be unliked """
    @user_required
    def post(self, post_id):
        """ If the user liked the post, removes their like """
        post = get_item('Post', post_id)
        if not post:
            self.error(404)
            self.render("404.html")
            return

        likes = [l.encode("utf-8") for l in post.likes]
        likes.remove(self.user.name)
        post.likes = likes
        post.put()
        self.redirect("/%s" % str(post.key.id()))

#### technically this should redirect to signup, not login
class Welcome(Handler):
    """ Provides the newly logged in user with a welcome message """
    @user_required
    def get(self):
        """ If the user is logged in, renders a welcome page """
        self.render('welcome.html', username=self.user.name)

# User Handlers

#### should probably check if user is already logged in
class Signup(Handler):
    """ Allows someone to register as a new user """
    def get(self):
        """ Renders the signup page"""
        self.render("signup.html")

    def post(self):
        """
        If the information provided is all valid, the information is passed on
        so that a new user can be created
        """
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')

        has_error = False
        params = dict(username=self.username, email=self.email,
                      password=self.password, verify=self.verify)

        if not valid_username(self.username):
            params['username_error'] = "Not a valid username"
            # This sets the "has-error" class for Bootstrap
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
    """ Allows the creation of a new user after receiving data from Signup """
    def done(self, params):
        """
        Check to see if the provided username already exists, otherwise,
        creates a new User entity
        """
        u = User.by_name(self.username)
        if u:
            params['username_error'] = "That user already exists."
            # This sets the "has-error" class for Bootstrap
            params['user_class'] = "has-error"
            self.render('signup.html', **params)
        else:
            u = User.register(self.username, self.password, self.email)
            u.put()

            self.login(u)
            self.redirect('/')


class Login(Handler):
    """ Allows registered users to login """
    def get(self):
        """ Renders the login page """
        self.render('login.html')

    def post(self):
        """
        If the provided credentials match credentials stored in the
        User database, the user is logged in
        """
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
    """ Allows the user to logout """
    def get(self):
        """ Logs the user out """
        self.logout()
        self.redirect('/signup')

# Comment Handlers


class AddComment(Handler):
    """ Allows for the creation of new comments """
    @user_required
    def post(self, post_id):
        """
        If the user is logged in, and the provided values are all valid, a new
        comment entity is created for the given post. If there is an error, a
        new comment template is rendered with the values provided
        """
        post = get_item('Post', post_id)
        if not post:
            self.error(404)
            self.render("404.html")
            return

        username = self.user.name
        comment_title = self.request.get("comment_title")
        comment_text = self.request.get("comment_text")
        params = dict(comment_title=comment_title,
                        comment_text=comment_text)
        has_error = False
        if not comment_title:
            # This sets the "has-error" class for Bootstrap
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



class EditComment(Handler):
    """" Allows for an already posted comment to be edited """
    @user_required
    def get(self, post_id, comment_id):
        """
        Renders the edit comment template with the values of the comment filled
        in if the logged in user is the user who created the comment
        """
        comment = get_item('Comment', comment_id)
        post = get_item('Post', post_id)
        if not post or not comment:
            self.error(404)
            self.render("404.html")
            return

        if comment.username == self.user.name:
            self.render('edit_comment.html', c=comment, p=post)
        else:
            error = "Only the user who created this comment can modify it."
            self.render("error.html", error=error)

    @user_required
    def post(self, post_id, comment_id):
        """
        Submits the changes to the comment, or deletes the comment if the
        logged in user is the user who created the comment
        """
        comment = get_item('Comment', comment_id)
        post = get_item('Post', post_id)
        if not post or not comment:
            self.error(404)
            self.render("404.html")
            return

        if comment.username == self.user.name:
            if self.request.get("action") == "edit":
                comment_title = self.request.get("comment_title")
                comment_text = self.request.get("comment_text")

                params = dict(comment_title=comment_title,
                              comment_text=comment_text, c=comment)
                has_error = False
                if not comment_title:
                    # This sets the "has-error" class for Bootstrap
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


class DeleteComment(Handler):
    """ Allows for a comment to be deleted """
    @user_required
    def post(self, post_id, comment_id):
        """ Runs post request to delete comments """
        comment = get_item('Comment', comment_id)
        post = get_item('Post', post_id)
        if not post or not comment:
            self.error(404)
            self.render("404.html")
            return

        if comment.username == self.user.name:
            ndb.Key('Comment', int(comment_id)).delete()
            self.redirect("/%s" % str(post_id))
        else:
            error = "Only the user who created this comment can modify it."
            self.render("error.html", error=error)


class LikeComment(Handler):
    """ Allows for a comment to be liked """
    @user_required
    def post(self, post_id, comment_id):
        """
        If the user didn't created the comment or already liked the comment,
        adds a new like to the comment
        """
        comment = get_item('Comment', comment_id)
        post = get_item('Post', post_id)
        if not post or not comment:
            self.error(404)
            self.render("404.html")
            return

        likes = [u.encode("utf-8") for u in comment.likes]
        username = self.user.name
        if username in likes or username == comment.username:
            self.redirect("/%s" % str(post_id))
        else:
            comment.likes.append(username)
            comment.put()
            self.redirect("/%s" % str(post_id))


class UnlikeComment(Handler):
    """ Allows users to unlike a comment """
    @user_required
    def post(self, post_id, comment_id):
        """ If the user liked the comment, removes their like """
        comment = get_item('Comment', comment_id)
        post = get_item('Post', post_id)
        if not post or not comment:
            self.error(404)
            self.render("404.html")
            return

        likes = [u.encode("utf-8") for u in comment.likes]
        username = self.user.name
        if username in likes or username == comment.username:
            likes.remove(username)
            comment.likes = likes
            comment.put()
            self.redirect("/%s" % str(post_id))
        else:
            self.redirect("/%s" % str(post_id))


app = webapp2.WSGIApplication([('/', Blog),
                               ('/new_post', AddPost),
                               ('/([0-9]+)', Permalink),
                               ('/([0-9]+)/edit', EditPost),
                               ('/([0-9]+)/delete', DeletePost),
                               ('/([0-9]+)/like', LikePost),
                               ('/([0-9]+)/unlike', UnlikePost),
                               ('/([0-9]+)/add_comment', AddComment),
                               ('/([0-9]+)/([0-9]+)/edit', EditComment),
                               ('/([0-9]+)/([0-9]+)/delete', DeleteComment),
                               ('/([0-9]+)/([0-9]+)/like', LikeComment),
                               ('/([0-9]+)/([0-9]+)/unlike', UnlikeComment),
                               ('/signup', Register),
                               ('/login', Login),
                               ('/welcome', Welcome),
                               ('/logout', Logout)],
                              debug=True)
