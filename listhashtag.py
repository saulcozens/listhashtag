from google.appengine.ext import webapp
from google.appengine.ext.webapp.util import run_wsgi_app
from google.appengine.api import urlfetch
import urllib
from urllib import unquote
from django.utils import simplejson as json
import re



class CheckList(webapp.RequestHandler):
	def get(self, username, listname, hashtag, since_id=None):
		matched=False
		url = "https://api.twitter.com/1/lists/statuses.json?owner_screen_name="+username+"&slug="+listname
		if (since_id != None) :
			url += "&since_id="+since_id
		hashtag_re = "#("+'|'.join(unquote(hashtag).split(',')) + ")"
		self.response.headers['Content-Type'] = 'text/plain'
		resp = urlfetch.fetch(url=url,
								method=urlfetch.GET)
		if resp.status_code == 200 :
			tweets=json.loads(resp.content)
			if len(tweets) > 0 :
				since_id = tweets[0]['id']
				for tweet in tweets:
					if re.search( hashtag_re, tweet["text"], re.I) :
						matched = True
						break
		else:
			self.response.set_status(500, "Something went wrong. Probably something to do with the twitter API call. Somebody should probably do something about it")


		self.response.out.write([matched,str(since_id)])
			


application = webapp.WSGIApplication(
									[(r'/([^/]*)/([^/]*)/([^/]*)', CheckList),  ## username, listname, hashtags
                   (r'/([^/]*)/([^/]*)/([^/]*)/(\d+)', CheckList)],  ## username, listname, hashtags, since_id
									debug=True)

def main():
	run_wsgi_app(application)

if __name__ == "__main__":
	main()