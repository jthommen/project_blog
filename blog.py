import hashlib
import hmac
import os
import random
import re
import string

import ghmns

import webapp2
import jinja2

from google.appengine.ext import ndb

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(
    loader=jinja2.FileSystemLoader(template_dir),
    autoescape=True)

# Creating secret values for user login system

# Function to generate random strings, with random & choice module
# secret = (''.join(random.choice(string.hexdigits) for i in range(50)))
# safe secret in external module and import as variable


def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(ghmns.secret, val).hexdigest())


def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val


def make_salt():
    return ''.join(random.choice(string.hexdigits) for i in xrange(5))


def make_pw_hash(name, pw, salt=None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s|%s' % (salt, h)


def valid_pw(name, password, h):
    salt = h.split('|')[0]
    if h == make_pw_hash(name, password, salt):
        return password


# Builds a random key that serves as ancestor
def ancestor_key():
    return ndb.Key('Blog', 'id')


# Google Cloud Data Store Model
class Post(ndb.Model):
    author = ndb.StringProperty(required=True)
    title = ndb.StringProperty(required=True)
    content = ndb.TextProperty(required=True)
    created = ndb.DateTimeProperty(auto_now_add=True)
    last_modified = ndb.DateTimeProperty(auto_now=True)


class Comment(ndb.Model):
    author = ndb.StringProperty(required=True)
    content = ndb.TextProperty(required=True)
    created = ndb.DateTimeProperty(auto_now_add=True)
    last_modified = ndb.DateTimeProperty(auto_now=True)
    post_id = ndb.StringProperty(required=True)


class Like(ndb.Model):
    post_id = ndb.StringProperty(required=True)
    author_id = ndb.StringProperty(required=True)
    status = ndb.BooleanProperty(required=True)


class User(ndb.Model):
    name = ndb.StringProperty(required=True)
    password_hash = ndb.StringProperty(required=True)
    email = ndb.StringProperty()

    @classmethod
    def get_by_name(cls, name):
        user = User.query(User.name == name).fetch(1)
        for u in user:
            return u

    @classmethod
    def login(cls, name, pw):
        u = cls.get_by_name(name)
        if u and pw == valid_pw(name, pw, u.password_hash):
            return u

    @classmethod
    def register(cls, username, pw, email=None):
        password_hash = make_pw_hash(username, pw)
        return User(name=username,
                    password_hash=password_hash,
                    email=email)


# Form validation functions using regular expressions
def valid_username(username):
    USER_RE = re.compile(r'^[a-zA-Z0-9_-]{3,20}$')
    return username and USER_RE.match(username)


def valid_password(password):
    PASS_RE = re.compile(r'^.{3,20}$')
    return password and PASS_RE.match(password)


def valid_email(email):
    EMAIL_RE = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
    return not email or EMAIL_RE.match(email)


# Helper functions that extend webapp2 RequestHandler
# class to help render templates
class HandlerHelper(webapp2.RequestHandler):

    # Helper function that takes a template name
    # and returns a string of that template
    def render_str(self, template, **kwargs):
        t = jinja_env.get_template(template)
        return t.render(**kwargs)

    # Helper function calls write on template
    # string instead of just returning a string
    def render(self, template, **kwargs):
        self.response.write(self.render_str(template, **kwargs))

    # Setting and checking for secure cookies
    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    # Login and logout helper functions
    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key.id()))

    def logout(self):
        self.response.headers.add_header(
            'Set-Cookie',
            'user_id=; Path=/')

    # checks if user is logged in
    def initialize(self, *args, **kwargs):
        webapp2.RequestHandler.initialize(self, *args, **kwargs)
        user_id = self.read_secure_cookie('user_id')
        self.user = user_id and User.get_by_id(int(user_id))


# Request Handlers for URL routing
class BlogFront(HandlerHelper):

    def get(self):
        self.render('front.html')


# Handler for the main post feed
class Feed(HandlerHelper):

    def render_feed(self, title="", content=""):
        # ndb orm query replaces gql query approach
        posts = Post.query(ancestor=ancestor_key()).order(-Post.created)
        user = self.user
        self.render("feed.html", posts=posts, user=user)

    def get(self):
        self.render_feed()


# Handler for signup form including error handling
class SignUp(HandlerHelper):

    def get(self):
        self.render('signup.html')

    def post(self):
        # Takes input from Form and saves them as variables
        have_error = False
        username = self.request.get('username')
        password = self.request.get('password')
        password_verify = self.request.get('password_verify')
        email = self.request.get('email')

        # Saves username & email for form to render again
        params = dict(username=username,
                      email=email)

        # Defines error messages after testing values
        # with form validation functions
        if not valid_username(username):
            params['error_username'] = "That's not a valid username."
            have_error = True

        if not valid_password(password):
            params['error_password'] = "That's not a valid password."
            have_error = True
        elif password != password_verify:
            params['error_password_verify'] = "Your passwords didn't match."
            have_error = True

        if not valid_email(email):
            params['error_mail'] = "That's not a valid email."
            have_error = True

        user = User.get_by_name(username)
        if user:
            if user.name == username:
                params['error_registered'] = "That name already exists."
                have_error = True

        if have_error:
            self.render('signup.html', **params)
        else:
            user = User.register(username, password, email)
            user.put()
            self.login(user)
            self.redirect('/feed')


# Handler for login page
class Login(HandlerHelper):

    def get(self):
        # Sets Cookie for Post redirect
        self.response.headers.add_header(
            'Set-Cookie',
            'referer=%s; Path=/' % self.request.referer)
        self.render('login.html', referer=self.request.referer)

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        user = User.login(username, password)
        if user:
            self.login(user)
            referer = str(self.request.cookies.get('referer'))
            if referer is None:
                self.redirect('/feed')
            else:
                self.redirect(referer)
        else:
            error = 'Invalid login'
            self.render('login.html', error=error)


# Handler for logout page
class Logout(HandlerHelper):

    def get(self):
        self.logout()
        self.redirect('/feed')


# Handler for page to create new post
class NewPost(HandlerHelper):

    def get(self):
        # Checks if a user is logged in, redirects to login otherwise
        if self.user:
            self.render('newpost.html', user=self.user)
        else:
            return self.redirect('/login')

    def post(self):

        if not self.user:
            return self.redirect('/login')

        else:
            title = self.request.get('title')
            content = self.request.get('content')
            author = self.user.name

            params = dict(title=title,
                          content=content)

            if title and content:
                post = Post(
                    parent=ancestor_key(),
                    author=author,
                    title=title,
                    content=content)
                post.put()
                # Redirects to permalink that is created
                # via post key id in Google Data Store
                self.redirect('/%s' % str(post.key.id()))
            else:
                params[
                    'error'] = "Please fill in both, post title and content."
                self.render('newpost.html', **params)


# Handler for page to edit posts
class EditPost(HandlerHelper):

    def get(self, post_id):
        post = Post.get_by_id(int(post_id), parent=ancestor_key())

        self.render('edit.html', post=post, referer=self.request.referer)

    def post(self, post_id):

        if not self.user:
            return self.redirect('/login')

        else:
            post = Post.get_by_id(int(post_id), parent=ancestor_key())
            user = self.user
            if not post:
                self.error(404)
            else:
                title = self.request.get('title')
                content = self.request.get('content')

            params = dict(title=title,
                          content=content,
                          request=self.request.referer)

            if user.name == post.author:
                if title and content:
                    post.title = title
                    post.content = content
                    post.put()
                    # Redirects to permalink that is created
                    # via post key id in Google Data Store
                    self.redirect('/%s' % str(post.key.id()))
                else:
                    params['error'] = """Please fill in both,
                        post title and content."""
                    self.render('edit.html', post=post, **params)
            else:
                params['error'] = "You can only edit your own posts."
                self.render('edit.html', post=post, **params)


# Handler for displaying a single post page
class PostPage(HandlerHelper):

    def get(self, post_id):
        key = ndb.Key('Post', int(post_id), parent=ancestor_key())
        post = key.get()

        if not post:
            self.error(404)
            return
        else:
            params = dict(post=post)
            params['comments'] = Comment.query(ancestor=ancestor_key()).filter(
                Comment.post_id == post_id).order(Comment.created)
            params['likes'] = Like.query(ancestor=ancestor_key()).filter(
                Like.post_id == post_id).count()

            # Sets Cookie for Post redirect
            self.response.headers.add_header(
                'Set-Cookie',
                'referer=%s; Path=/' % self.request.referer)

            if self.user:
                user = self.user
                params['user'] = user

                if user.name == post.author:
                    self.response.headers.add_header(
                        'Set-Cookie',
                        'error=; Path=/')
                    self.render('post.html', **params)

                else:
                    params['error'] = self.request.cookies.get('error')
                    self.render('post.html', **params)
            else:
                self.render('post.html', **params)

    # Function to create comments
    def post(self, post_id):

        if not self.user:
            return self.redirect('/login')

        else:
            author = self.user.name
            content = self.request.get('comment')
            post = Post.get_by_id(int(post_id), parent=ancestor_key())

            # Create comments
            if post:
                if content:
                    comment = Comment(
                        parent=ancestor_key(),
                        author=author,
                        content=content,
                        post_id=post_id)
                    comment.put()
                    # Redirects to permalink that is created
                    # via post key id in Google Data Store
                    self.redirect('/%s' % str(post.key.id()))
                else:
                    error = "Please write a comment before submitting."
                    self.response.headers.add_header(
                        'Set-Cookie',
                        'error="%s"; Path=/' % error)
                    self.redirect('/%s' % str(post.key.id()))
            else:
                self.error(404)
                return


# Handler to delete a post
class DeletePost(HandlerHelper):

    def get(self):
        referer = str(self.request.cookies.get('referer'))
        self.redirect(referer)

    def post(self):
        if not self.user:
            return self.redirect('/login')

        else:
            user = self.user
            post_id = self.request.get('post_id')
            post = Post.get_by_id(int(post_id), parent=ancestor_key())

            if not post:
                self.error(404)
                return
            else:
                if post.author == user.name:
                    post.key.delete()
                self.redirect('/feed')


# Handler to edit a comment
class EditComment(HandlerHelper):

    def get(self, comment_id):
        comment = Comment.get_by_id(int(comment_id), parent=ancestor_key())

        self.render(
            'editcomment.html',
            comment=comment,
            referer=self.request.referer
            )

    def post(self, comment_id):

        if not self.user:
            return self.redirect('/login')

        else:
            comment = Comment.get_by_id(int(comment_id), parent=ancestor_key())
            user = self.user

            if not comment:
                self.error(404)
            else:
                content = self.request.get('content')

            params = dict(content=content)
            params['referer'] = self.request.referer

            if user.name == comment.author:
                if content:
                    comment.content = content
                    comment.put()
                    # Redirects to permalink that is created
                    # via post key id in Google Data Store
                    self.redirect('/%s' % str(comment.post_id))
                else:
                    params['error'] = "Please write some text."
                    self.render('editcomment.html', comment=comment, **params)
            else:
                params['error'] = "You can only edit your own posts."
                self.render('editcomment.html', comment=comment, **params)


# Handler to delete a comment
class DeleteComment(HandlerHelper):

    def get(self):
        referer = str(self.request.cookies.get('referer'))
        self.redirect(referer)

    def post(self):
        referer = str(self.request.cookies.get('referer'))

        if not self.user:
            return self.redirect('/login')

        else:
            user = self.user
            comment_id = self.request.get('comment_id')
            comment = Comment.get_by_id(int(comment_id), parent=ancestor_key())

            if not comment:
                self.error(404)
                return
            else:
                if comment.author == user.name:
                    comment.key.delete()
                self.redirect(referer)


# Handler to add a like
class AddLike(HandlerHelper):

    def get(self):
        referer = str(self.request.cookies.get('referer'))
        self.redirect(referer)

    def post(self):
        referer = os.environ['HTTP_REFERER']

        if not self.user:
            return self.redirect('/login')

        else:
            user_name = self.user.name
            post_id = self.request.get('post_id')
            post = Post.get_by_id(int(post_id), parent=ancestor_key())

            # Adding likes
            if user_name != post.author:
                like = Like.query(ancestor=ancestor_key()).filter(
                    Like.post_id == post_id,
                    Like.author_id == user_name).count()
                if like > 0:
                    error = "You can't like something twice!"
                    self.response.headers.add_header(
                        'Set-Cookie',
                        'error="%s"; Path=/' % error)
                    self.redirect(referer)
                else:
                    like = Like(
                        parent=ancestor_key(),
                        post_id=post_id,
                        author_id=user_name,
                        status=True)
                    like.put()
                    self.redirect(referer)
            else:
                error = "You can't like your own posts."
                self.response.headers.add_header(
                    'Set-Cookie',
                    'error=%s; Path=/' % error)
                self.redirect(referer)


routes = [
    ('/', BlogFront),
    ('/signup', SignUp),
    ('/feed', Feed),
    ('/newpost', NewPost),
    ('/deletepost', DeletePost),
    ('/([0-9]+)', PostPage),
    ('/([0-9]+)/edit', EditPost),
    ('/login', Login),
    ('/logout', Logout),
    ('/editcomment/([0-9]+)', EditComment),
    ('/deletecomment', DeleteComment),
    ('/addlike', AddLike)
]

app = webapp2.WSGIApplication(routes=routes, debug=True)
