from google.appengine.ext import webapp
from google.appengine.ext.webapp.util import run_wsgi_app
import os
from google.appengine.ext.webapp import template
from google.appengine.api import urlfetch
import urllib
from urllib import unquote
from django.utils import simplejson as json
import re
from twitter_oauth_handler import *
   

class CheckList(webapp.RequestHandler):
	def get(self, username, listname, hashtag, since_id=None):
		
		client = OAuthClient('twitter', self)
		
		matched=False
		url = "https://api.twitter.com/1/lists/statuses.json"
		hashtag_re = "#("+'|'.join(unquote(hashtag).split(',')) + ")"
		self.response.headers['Content-Type'] = 'text/plain'
		if (since_id != None) :
			tweets=client.get(url, (200,), owner_screen_name=username, slug=listname, since_id=since_id)
		else:
			tweets=client.get(url, (200,), owner_screen_name=username, slug=listname)

		if len(tweets) > 0 :
			since_id = tweets[0]['id']
			for tweet in tweets:
				if re.search( hashtag_re, tweet["text"], re.I) :
					matched = True
					break

		self.response.out.write([matched,str(since_id)])
			

class IndexPage(webapp.RequestHandler):
		def get(self) :
			path = os.path.join(os.path.dirname(__file__), 'index.html')
			self.response.out.write(template.render(path, {}))		

application = webapp.WSGIApplication([(r'/oauth/(.*)/(.*)', OAuthHandler),
                                      (r'/[^/]*', IndexPage),
                                      (r'/([^/]*)/([^/]*)/([^/]*)', CheckList),  ## username, listname, hashtags
                                      (r'/([^/]*)/([^/]*)/([^/]*)/(\d+)', CheckList)],  ## username, listname, hashtags, since_id
                                     debug=True)

def main():
	run_wsgi_app(application)

if __name__ == "__main__":
	main()