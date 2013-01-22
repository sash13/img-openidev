#!/usr/bin/env python2
#
# Copyright 2007 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

import cgi
import time
import urllib
import webapp2
import hashlib

from google.appengine.ext import db
from google.appengine.api import images
from google.appengine.api import users



#from http://webapp-improved.appspot.com/api/webapp2_extras/appengine/users.html
def admin_required(handler_method):
    """A decorator to require that a user be an admin for this application
    to access a handler.

    To use it, decorate your get() method like this::

        @admin_required
        def get(self):
            user = users.get_current_user(self)
            self.response.out.write('Hello, ' + user.nickname())

    We will redirect to a login page if the user is not logged in. We always
    redirect to the request URI, and Google Accounts only redirects back as
    a GET request, so this should not be used for POSTs.
    """
    def check_admin(self, *args, **kwargs):
        if self.request.method != 'GET':
            self.abort(400, detail='The admin_required decorator '
                'can only be used for GET requests.')

        user = users.get_current_user()
        if not user:
            return self.redirect(users.create_login_url(self.request.url))
        elif not users.is_current_user_admin():
            self.abort(403)
        else:
            handler_method(self, *args, **kwargs)

    return check_admin

class Images(db.Model):
  name = db.StringProperty()
  img = db.BlobProperty()
  mimeType = db.StringProperty()
  date = db.DateTimeProperty(auto_now_add=True)

class LogsDb(db.Model):
  date = db.DateTimeProperty(auto_now_add=True)
  url = db.StringProperty()
  referer = db.StringProperty()
  ip_address = db.StringProperty()

class MainPage(webapp2.RequestHandler):
  def get(self):
    self.redirect("http://blog.openidev.ru")


class LogPage(webapp2.RequestHandler):
  @admin_required
  def get(self):
    self.response.out.write('<html><body>')

    logs = db.GqlQuery("SELECT * "
                            "FROM LogsDb "
                            "ORDER BY date DESC LIMIT 10")

    for log in logs:
      self.response.out.write('%s <b>%s</b> %s <br>' % (log.date, log.ip_address, log.url))

class uploadPage(webapp2.RequestHandler):
  @admin_required
  def get(self):
    self.response.out.write("""
          <form action="/upload" enctype="multipart/form-data" method="post">
            <div><input type="file" name="img"/></div>
            <div><input type="submit" value="upload"></div>
          </form>
        </body>
      </html>""")

  def post(self):
    imageObj = Images()
    image = self.request.POST.get('img',None)
    if image is None : return self.error(400)

    contentType = getContentType( image.filename )
    if contentType is None: 
      self.response.out.write("Unsupported image type")
      return

    imageObj.mimeType = contentType
    imageObj.img = db.Blob(image.file.read())
    imageObj.name = image.filename
    imageObj.put()
    self.response.write('image uploaded with url <br> http://%s/load/%s.%s <br> <img src="http://%s/load/%s.%s">' % (self.request.headers.get('host', 'no host'), imageObj.key(), image.filename.split('.')[-1].lower(),
      self.request.headers.get('host', 'no host'), imageObj.key(), image.filename.split('.')[-1].lower()))

class ImageHandler(webapp2.RequestHandler):
  def get(self, image_url):
    user_agent = self.request.headers.get('User-Agent')
    if 'Feedfetcher' in user_agent:
      self.redirect("http://www.google.com/feedfetcher.html")
      return

    image = None

    try:
      image = Images.get(image_url.split('.')[0])
      if not image: raise "Not found"
    except:
      self.error(404)
      '''with open("default.jpg", 'r') as f:
        default_img = f.read()
      self.response.headers['Content-Type'] = 'image/jpeg'
      self.response.out.write(default_img)'''
      loggin(self, '404')
      self.redirect('http://%s/404.jpg' % self.request.headers.get('host', 'no host'))
      return

    loggin(self, image_url)

    self.response.headers['Content-Type'] = str(image.mimeType)
    self.response.out.write(image.img)

def loggin(object, image_url):
  ip = object.request.remote_addr
  referer = object.request.referer
  log = LogsDb()
  log.ip_address = ip
  log.referer = referer
  log.url = image_url
  log.put()

def getContentType( filename ): # lists and converts supported file extensions to MIME type
  ext = filename.split('.')[-1].lower()
  if ext == 'jpg' or ext == 'jpeg': return 'image/jpeg'
  if ext == 'png': return 'image/png'
  if ext == 'gif': return 'image/gif'
  if ext == 'svg': return 'image/svg+xml'
  return None

app = webapp2.WSGIApplication([
  ('/', MainPage),
  ('/logs', LogPage),
  ('/upload', uploadPage),
  (r'/load/(.*)', ImageHandler)
], debug=True)
