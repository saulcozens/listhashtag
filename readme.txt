listhashtag

Born for the need to monitor twitter for a specific hashtag for an arduino project, this Python (GAE) script allows you to check to see if any of a specified list of hashtags have been mentioned by anyone in a specified twitter list.

The script has been written in a very generic way to allwo it to be re-used for any application that wants to monitor a specific set of twitter feeds for hashtags and get a yes/no answer.

Exciting yeah?  To use it run the code as a Google App Engine application and pass your parameteres in on the request

  http://yourapplicationname.appspot.com/<username>/<listname>/<comma separated list of hashtags>/<id of the last tweet checked>

you will return a (very) simple JSON struture in return:
  [matched, '199264308323037184']
  
If hosted on the Google App Engine, this script will share its rate limit allocation with many other GAE apps. So you will see a high proportion of twitter API failures.  I will get round to fixing that ASAP.
