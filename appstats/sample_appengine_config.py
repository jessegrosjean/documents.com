#!/usr/bin/python2.4
#
# Copyright 2009 Google Inc. All Rights Reserved.

"""Sample AppStats Configuration.

There are four sections:

0) WSGI middleware declaration.
1) Django version declaration.
2) Configuration constants.
3) Configuration functions.

"""

__author__ = 'guido@google.com (Guido van Rossum)'

# 0) WSGI middleware declaration.

# Only use this if you're not Django; with Django, it's easier to add
#   'appstats.recording.AppStatsDjangoMiddleware',
# to your Django settings.py file.

## def webapp_add_wsgi_middleware(app):
##   from appstats import recording
##   app = recording.appstats_wsgi_middleware(app)
##   return app


# 1) Django version declaration.

# If your application uses Django and requires a specific version of
# Django, uncomment the following block of three lines.  Currently
# supported values for the Django version are '0.96' (the default),
# '1.0', and '1.1'.

## from google.appengine.dist import use_library
## use_library('django', '1.0')
## import django


# 2) Configuration constants.

# DEBUG: True of False.  When True, verbose messages are logged at the
# DEBUG level.  Also, this flag is causes tracebacks to be shown in
# the web UI when an exception occurs.  (Tracebacks are always logged
# at the ERROR level as well.)

appstats_DEBUG = False  # Whether to call logging.debug(); also used in ui.py.

# DUMP_LEVEL: -1, 0, 1 or 2.  Controls how much debug output is
# written to the logs by the internal dump() function during event
# recording.  -1 dumps nothing; 0 dumps one line of information; 1
# dumps more informat and 2 dumps the maximum amount of information.
# You would only need to change this if you were debugging the
# recording implementation.

appstats_DUMP_LEVEL = -1  # How much stuff to dump on save(); -1 means none.

# The following constants control the resolution and range of the
# memcache keys used to record information about individual requests.
# Two requests that are closer than KEY_DISTANCE milliseconds will be
# mapped to the same key (thus losing all information about the
# earlier of the two requests).  Up to KEY_MODULUS distinct keys are
# generated; after KEY_DISTANCE * KEY_MODULUS milliseconds the key
# values roll over.  Increasing KEY_MODULUS causes a proportional
# increase of the amount of data saved in memcache.  Increasing
# KEY_DISTANCE causes a requests during a larger timespan to be
# recorded, at the cost of increasing risk of assigning the same key
# to two adjacent requests.

appstats_KEY_DISTANCE = 100  # Number of milliseconds between distinct keys.
appstats_KEY_MODULUS = 1000  # Number of distinct keys.

# The following constants control the namespace and key values used to
# store information in memcache.  You can safely leave this alone.

appstats_KEY_NAMESPACE = '__appstats__'  # Namespace.
appstats_KEY_PREFIX = '__appstats__'  # Prefix for memcache keys.
appstats_KEY_TEMPLATE = ':%06d'  # Template for timestamp substitution in key.
appstats_PART_SUFFIX = ':part'  # Memcache key suffix for summary entries.
appstats_FULL_SUFFIX = ':full'  # Memcache key suffix for full entries.
appstats_LOCK_SUFFIX = '<lock>'  # Memcache key suffix for lock entry.

# Numerical limits on how much information is saved for each event.
# MAX_STACK limits the number of stack frames saved; MAX_LOCALS limits
# the number of local variables saved per stack frame.  MAX_REPR
# limits the length of the string representation of each variable
# saved; MAX_DEPTH limits the nesting depth used when computing the
# string representation of structured variables (e.g. lists of lists).

appstats_MAX_STACK = 10  # Max number of stack frames per call to record.
appstats_MAX_LOCALS = 10  # Max number of locals per frame to record.
appstats_MAX_REPR = 100  # Max output string length of format_value().
appstats_MAX_DEPTH = 10  # Max depth for format_value().

# Regular expressions.  These are matched against the 'code key' of a
# stack frame, which is a string of the form
# '<filename>:<function>:<lineno>'.  If the code key of a stack frame
# matches RE_STACK_BOTTOM, it and all remaining stack frames are
# skipped.  If the code key matches RE_STACK_SKIP, that frame is not
# saved but subsequent frames may be saved.

appstats_RE_STACK_BOTTOM = r'dev_appserver\.py'
appstats_RE_STACK_SKIP = r'recording\.py|apiproxy_stub_map\.py'

# Timeout for memcache lock management, in seconds.

appstats_LOCK_TIMEOUT = 1

# Timezone offset.  This is used to convert recorded times (which are
# all in UTC) to local time.  The default is US/Pacific winter time.

appstats_TZOFFSET = 8*3600

# URL path (sans host) leading to the stats UI.  Should match app.yaml.

appstats_stats_url = '/stats'

# 3) Configuration functions.

# These functions are called by the UI code only; they don't affect
# the recorded information.

# normalize_path() takes a path and returns an 'path key'.  The path
# key is used by the UI to compute statistics for similar URLs.  If
# your application has a large or infinite URL space (e.g. each issue
# in an issue tracker might have its own numeric URL), this function
# can be used to produce more meaningful statistics.

def appstats_normalize_path(path):
  return path

# extract_key() is a lower-level function with the same purpose as
# normalize_key().  It can be used to lump different request methods
# (e.g. GET and POST) together, or conversely to use other information
# on the request object (mostly the query string) to produce a more
# fine-grained path key.  The argument is a StatsProto object; this is
# a class defined in recording.py.  Useful methods are:
#
#   - http_method()
#   - http_path()
#   - http_query()
#   - http_status()
#
# Note that the StatsProto argument is loaded only with summary
# information; this means you cannot access the request headers.

def appstats_extract_key(request):
  key = appstats_normalize_path(request.http_path())
  if request.http_method() != 'GET':
    key = '%s %s' % (request.http_method(), key)
  return key
