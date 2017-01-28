import os

import webapp2
import jinja2

from google.appengine.ext import ndb

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir), autoescape = True)



# Helper functions that extend webapp2 RequestHandler class to help render templates
class HandlerHelper(webapp2.RequestHandler):

    # Helper function that takes a template name and returns a string of that template
    def render_str(self, template, **kwargs):
        t = jinja_env.get_template(template)
        return t.render(**kwargs)

    # Helper function calls write on template string instead of just returning a string
    def render(self, template, **kwargs):
        self.response.write(self.render_str(template, **kwargs))

# Google Cloud Data Store Model

def blog_key(name="default"):
    return db.Key.from_path('blogs', name)


# Request Handlers for URL routing
class BlogFront(HandlerHelper):
    def get(self):
        self.render('front.html')

class SignUp(HandlerHelper):
    def get(self):
        self.render('signup.html')

    def post(self):
        have_error = False
        username = self.request.get('username')
        password = self.request.get('password')
        password_verify = self.request.get('password_verify')
        email = self.request.get('email')

routes = [
    ('/', BlogFront),
    ('/signup', SignUp)
]

app = webapp2.WSGIApplication(routes=routes, debug = True)