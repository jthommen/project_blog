import os
import re

import webapp2
import jinja2

from google.appengine.ext import ndb

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir), autoescape = True)



#Google Cloud Data Store Model

# Setting parent key for anchestor/parent (don't know how it works exactly...)
# def blog_key(name="default"):
    # return db.Key.from_path('blogs', name)

#


class Post(ndb.Model):
    title = ndb.StringProperty(required = True)
    content = ndb.TextProperty(required = True)
    created = ndb.DateTimeProperty(auto_now_add = True)
    last_modified = ndb.DateTimeProperty(auto_now = True)


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


# Request Handlers for URL routing
class BlogFront(HandlerHelper):
    def get(self):
        self.render('front.html')

class Feed(HandlerHelper):
    def render_feed(self, title="", content=""):
        username = self.request.get('username')
        posts = ndb.GqlQuery("SELECT * FROM Post ORDER BY created DESC")
        self.render("feed.html", title=title, content=content, username=username)

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


        if have_error:
            self.render('signup.html', **params)
        else:
            self.redirect('/feed?username=' + username)

class NewPost(HandlerHelper):
    def get(self):
        self.render('newpost.html')

    def post(self):
        title = self.request.get('title')
        content = self.request.get('content')

        params = dict(title = title,
                      content = content)

        if title and content:
            Post(title = title, content = content).put()
            self.redirect('/feed')
        else:
            params['error'] = "Please fill in both, post title and content."
            self.render('newpost.html', **params)

routes = [
    ('/', BlogFront),
    ('/signup', SignUp),
    ('/feed', Feed),
    ('/newpost', NewPost)
]

app = webapp2.WSGIApplication(routes=routes, debug = True)