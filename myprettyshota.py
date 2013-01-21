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
import base64
import cgi
import datetime
import time
import urllib
import logging
import webapp2
import hashlib

from google.appengine.ext import db
from google.appengine.api import images
from google.appengine.api import users
from google.appengine.api.logservice import logservice


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

class LogPageAlternative(webapp2.RequestHandler):
    @admin_required
    def get(self):
        #logging.info('Starting Main handler')
        # Get the incoming offset param from the Next link to advance through
        # the logs. (The first time the page is loaded, there won't be any offset.)
        try:
            offset = self.request.get('offset') or None
            if offset:
                offset = base64.urlsafe_b64decode(str(offset))
        except TypeError:
            offset = None

        # Set up end time for our query.
        end_time = time.time()

        # Count specifies the max number of RequestLogs shown at one time.
        # Use a boolean to initially turn off visiblity of the "Next" link.
        count = 5
        show_next = False
        last_offset = None

        # Iterate through all the RequestLog objects, displaying some fields and
        # iterate through all AppLogs beloging to each RequestLog count times.
        # In each iteration, save the offset to last_offset; the last one when
        # count is reached will be used for the link.
        i = 0
        for req_log in logservice.fetch(end_time=end_time, offset=offset,
                                        minimum_log_level=logservice.LOG_LEVEL_INFO,
                                        include_app_logs=True):
            #self.response.out.write('<br /> REQUEST LOG <br />')
            self.response.out.write(
                'IP: %s  Nickname: %s  Resource: %s  Referrer: %s ' %
                (req_log.ip, req_log.nickname, req_log.resource, req_log.referrer))
            self.response.out.write(
                'Date: %s<br />' %
                datetime.datetime.fromtimestamp(req_log.end_time).strftime('%D %T UTC'))

            last_offset= req_log.offset
            i += 1

            '''for app_log in req_log.app_logs:
                self.response.out.write('<br />APP LOG<br />')
                self.response.out.write(
                    'Date: %s<br />' %
                    datetime.datetime.fromtimestamp(app_log.time).strftime('%D %T UTC'))
                self.response.out.write('<br />Message: %s<br />' % app_log.message)'''

            if i >= count:
                show_next = True
                break

        # Prepare the offset URL parameters, if any.
        if show_next:
            query = self.request.GET
            query['offset'] = base64.urlsafe_b64encode(last_offset)
            next_link = urllib.urlencode(query)
            self.response.out.write('<a href="/logs2?%s">Next</a>' % next_link)


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
    image = None

    try:
      image = Images.get(image_url.split('.')[0])
      if not image: raise "Not found"
    except:
      self.error(404)
      with open("default.jpg", 'r') as f:
        default_img = f.read()
      self.response.headers['Content-Type'] = 'image/jpeg'
      '''self.response.out.write( "Could not find image: '%s'" % id )'''
      self.response.out.write(default_img)
      loggin(self, '404')
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
  ('/logs2', LogPageAlternative),
  ('/upload', uploadPage),
  (r'/load/(.*)', ImageHandler)
], debug=True)
