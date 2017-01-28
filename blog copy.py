import logging
import os

import webapp2
import jinja2

from google.appengine.ext import ndb

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir), autoescape = True)

# Custom error handling
def handle_404(request, response, exception):
    logging.exception(exception)
    response.write('Oops! I could swear this page was here not long ago!')
    response.set_status(404)

def handle_500(request, response, exception):
    logging.exception(exception)
    response.write("The server ghosts weren't friendly today!")
    response.set_status(500)


# Helper functions that extend webapp2 RequestHandler class
class HandlerHelper(webapp2.RequestHandler):

    # Helper function that takes a template name and returns a string of that template
    def render_str(self, template, **kwargs):
        t = jinja_env.get_template(template)
        return t.render(**kwargs)

    # Helper function calls write on template string instead of just returning a string
    def render(self, template, **kw):
        self.response.write(self.render_str(template, **kw))

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

app.error_handlers[404] = handle_404
app.error_handlers[500] = handle_500