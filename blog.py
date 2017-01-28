import os

import webapp2
import jinja2

from google.appengine.ext import ndb

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir), autoescape = True)



# Helper functions that extend webapp2 RequestHandler class
class HandlerHelper(webapp2.RequestHandler):

    # Helper function that takes a template name and returns a string of that template
    def render_str(self, template):
        t = jinja_env.get_template(template)
        return t.render()

    # Helper function calls write on template string instead of just returning a string
    def render(self, template):
        self.response.write(self.render_str(template))

# Google Cloud Data Store Model

def blog_key(name="default"):
    return db.Key.from_path('blogs', name)


# Request Handlers for URL routing
class BlogFront(HandlerHelper):
    def get(self):
        self.render('front.html')

routes = [
    ('/', BlogFront)
]

app = webapp2.WSGIApplication(routes=routes, debug = True)