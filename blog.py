import hashlib
import hmac
import os
import random
import re
from string import letters

import webapp2
import jinja2

from google.appengine.ext import ndb

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir), autoescape = True)

#Creating secret values for user login system

#Function to generate random strings, with random & choice module
#secret = (''.join(choice(hexdigits) for i in range(50)))

secret = 'B204bd3CDBca3f35e4AB0Cb7cEe2Fd2FcA30B06267cF58d5de'

def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())

#Builds a random key that serves as ancestor
def ancestor_key():
    return ndb.Key('Blog', 'id')

#Google Cloud Data Store Model
class Post(ndb.Model):
    title = ndb.StringProperty(required = True)
    content = ndb.TextProperty(required = True)
    created = ndb.DateTimeProperty(auto_now_add = True)
    last_modified = ndb.DateTimeProperty(auto_now = True)


class User(ndb.Model):
    name = ndb.StringProperty(required = True)
    password = ndb.StringProperty(required = True)
    email = ndb.StringProperty()

    @classmethod
    def get_by_name(cls, name):
        user = User.query(User.name==name).fetch(1)
        for u in user:
            return u

    @classmethod
    def login(cls, name):
        u = cls.get_by_name(name)
        if u:
            return u

# Form validation functions using regular expressions
USER_RE = re.compile(r'^[a-zA-Z0-9_-]{3,20}$')
def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r'^.{3,20}$')
def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):
    return not email or EMAIL_RE.match(email)


# Helper functions that extend webapp2 RequestHandler class to help render templates
class HandlerHelper(webapp2.RequestHandler):

    # Helper function that takes a template name and returns a string of that template
    def render_str(self, template, **kwargs):
        t = jinja_env.get_template(template)
        return t.render(**kwargs)

    # Helper function calls write on template string instead of just returning a string
    def render(self, template, **kwargs):
        self.response.write(self.render_str(template, **kwargs))

    # Setting and checking for secure cookies
    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    # Login and logout helper functions
    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key.id()))


# Request Handlers for URL routing
class BlogFront(HandlerHelper):
    def get(self):
        self.render('front.html')

class Feed(HandlerHelper):
    def render_feed(self, title="", content=""):
        #ndb orm query replaces gql query approach
        posts = Post.query(ancestor=ancestor_key()).order(-Post.created)
        self.render("feed.html", posts=posts)

    def get(self):
        self.render_feed()

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
        params = dict(username = username,
                      email = email)

        # Defines error messages after testing values with form validation functions
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
            user = User(name=username, password=password, email=email)
            user.put()
            self.login(user)
            self.redirect('/feed')


class Login(HandlerHelper):
    def get(self):
        self.render('login.html')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        user = User.login(username, password)
        if user:
            self.login(user)
            self.redirect('/newpost')
        else:
            error = 'Invalid login'
            self.render('login.html', error= error)

class NewPost(HandlerHelper):
    def get(self):
        if self.user:
            self.render('newpost.html')
        else:
            self.redirect('/login')

    def post(self):
        title = self.request.get('title')
        content = self.request.get('content')

        params = dict(title = title,
                      content = content)

        if title and content:
            post = Post(parent=ancestor_key(), title = title, content = content)
            post.put()
            # Redirects to permalink that is created vi post key id in Google Data Store
            self.redirect('/%s' % str(post.key.id()))
        else:
            params['error'] = "Please fill in both, post title and content."
            self.render('newpost.html', **params)

class PostPage(HandlerHelper):
    def get(self, post_id):
        key = ndb.Key('Post', int(post_id), parent=ancestor_key())
        post = key.get()

        if not post:
            self.error(404)
            return

        self.render('post.html', post=post)

routes = [
    ('/', BlogFront),
    ('/signup', SignUp),
    ('/feed', Feed),
    ('/newpost', NewPost),
    ('/([0-9]+)', PostPage),
    ('/login', Login)
]

app = webapp2.WSGIApplication(routes=routes, debug = True)