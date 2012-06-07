# Twiddla Client Library
# http://www.twiddla.com/API/Reference.aspx
#
# NOTE: most of this was swiped from Twiddla's Python Library: 
# https://github.com/stripe/stripe-python/blob/master/stripe/__init__.py

import logging
import os
import platform
import sys
import urllib
import textwrap
import time
import datetime
import types




# - Requests is the preferred HTTP library
# - Google App Engine has urlfetch
# - Use Pycurl if it's there (at least it verifies SSL certs)
# - Fall back to urllib2 with a warning if needed
_httplib = None

try:
	from google.appengine.api import urlfetch
	_httplib = 'urlfetch'
except ImportError:
	pass

if not _httplib:
	try:
		import requests
		_httplib = 'requests'
	except ImportError:
		pass

	try:
		# Require version 0.8.8, but don't want to depend on distutils
		version = requests.__version__
		major, minor, patch = [int(i) for i in version.split('.')]
	except:
		# Probably some new-fangled version, so it should support verify
		pass
	else:
		if minor < 8 or (minor == 8 and patch < 8):
			print >>sys.stderr, 'Warning: the Twiddla library requires that your Python "requests" library has a version no older than 0.8.8, but your "requests" library has version %s. Twiddla will fall back to an alternate HTTP library, so everything should work, though we recommend upgrading your "requests" library. (HINT: running "pip install -U requests" should upgrade your requests library to the latest version.)' % (version, )
			_httplib = None

if not _httplib:
	try:
		import pycurl
		_httplib = 'pycurl'
	except ImportError:
		pass

if not _httplib:
	try:
		import urllib2
		_httplib = 'urllib2'
		print >>sys.stderr, "Warning: the Twiddla library is falling back to urllib2 because pycurl isn't installed. urllib2's SSL implementation doesn't verify server certificates. For improved security, we suggest installing pycurl."
	except ImportError:
		pass

if not _httplib:
	raise ImportError("Twiddla requires one of pycurl, Google App Engine's urlfetch, or urllib2.")


class APICaller(object):
	def __init__(self, username=None, password=None):
		self.username = username
		self.password = password
		self.message = ''


	def call(self, url, params={}):
		"""
		Mechanism for issuing an API call
		"""
		
		if self.username is None or self.password is None:
			self.message = 'No user/pass provided.'
			return False

		params = params.copy()
		meth = 'post'
		headers = {}

		if _httplib == 'requests':
			rbody, rcode = self.requests_request(meth, abs_url, headers, params)
		elif _httplib == 'pycurl':
			rbody, rcode = self.pycurl_request(meth, abs_url, headers, params)
		elif _httplib == 'urlfetch':
			rbody, rcode = self.urlfetch_request(meth, abs_url, headers, params)
		elif _httplib == 'urllib2':
			rbody, rcode = self.urllib2_request(meth, abs_url, headers, params)
		else:
			raise Exception("Can't find _httplib")

		self.html = rbody
		if not (200 == rcode):
			self.message = rbody
			return False
			
		if (rbody.startswith('-1')):
			self.message = rbody
			return False
			
		return True

	def pycurl_request(self, meth, abs_url, headers, params):
		s = StringIO.StringIO()
		curl = pycurl.Curl()

		meth = meth.lower()
		if meth == 'get':
			curl.setopt(pycurl.HTTPGET, 1)
			# TODO: maybe be a bit less manual here
			if params:
					abs_url = '%s?%s' % (abs_url, self.encode(params))
		elif meth == 'post':
			curl.setopt(pycurl.POST, 1)
			curl.setopt(pycurl.POSTFIELDS, self.encode(params))
		elif meth == 'delete':
			curl.setopt(pycurl.CUSTOMREQUEST, 'DELETE')
			if params:
					abs_url = '%s?%s' % (abs_url, self.encode(params))
		else:
			raise Exception('Unrecognized HTTP method %r.	This may indicate a bug in the Twiddla bindings.	Please contact info@twiddla.com for assistance.' % (meth, ))

		# pycurl doesn't like unicode URLs
		abs_url = self._utf8(abs_url)
		curl.setopt(pycurl.URL, abs_url)
		curl.setopt(pycurl.WRITEFUNCTION, s.write)
		curl.setopt(pycurl.NOSIGNAL, 1)
		curl.setopt(pycurl.CONNECTTIMEOUT, 30)
		curl.setopt(pycurl.TIMEOUT, 80)
		curl.setopt(pycurl.HTTPHEADER, ['%s: %s' % (k, v) for k, v in headers.iteritems()])
		if verify_ssl_certs:
			curl.setopt(pycurl.CAINFO, os.path.join(os.path.dirname(__file__), 'data/ca-certificates.crt'))
		else:
			curl.setopt(pycurl.SSL_VERIFYHOST, False)

		try:
			curl.perform()
		except pycurl.error, e:
			self.handle_pycurl_error(e)
		rbody = s.getvalue()
		rcode = curl.getinfo(pycurl.RESPONSE_CODE)
		return rbody, rcode

	def handle_pycurl_error(self, e):
		if e[0] in [pycurl.E_COULDNT_CONNECT,
								pycurl.E_COULDNT_RESOLVE_HOST,
								pycurl.E_OPERATION_TIMEOUTED]:
			msg = "Could not connect to Twiddla (%s).	Please check your internet connection and try again." % (api_base, )
		elif e[0] == pycurl.E_SSL_CACERT or e[0] == pycurl.E_SSL_PEER_CERTIFICATE:
			msg = "Could not verify Twiddla's SSL certificate.	Please make sure that your network is not intercepting certificates.	(Try going to %s in your browser.)	If this problem persists, let us know at info@twiddla.com." % (api_base, )
		else:
			msg = "Unexpected error communicating with Twiddla.	If this problem persists, let us know at info@twiddla.com."
		msg = textwrap.fill(msg) + "\n\n(Network error: " + e[1] + ")"
		raise Exception(msg)

	def urlfetch_request(self, meth, abs_url, headers, params):
		args = {}
		if meth == 'post':
			args['payload'] = self.encode(params)
		elif meth == 'get' or meth == 'delete':
			abs_url = '%s?%s' % (abs_url, self.encode(params))
		else:
			raise Exception('Unrecognized HTTP method %r.	This may indicate a bug in the Twiddla bindings.	Please contact info@twiddla.com for assistance.' % (meth, ))
		args['url'] = abs_url
		args['method'] = meth
		args['headers'] = headers
		args['validate_certificate'] = verify_ssl_certs
		# GAE requests time out after 60 seconds, so make sure we leave
		# some time for the application to handle a slow Twiddla
		args['deadline'] = 55

		try:
			result = urlfetch.fetch(**args)
		except urlfetch.Error, e:
			self.handle_urlfetch_error(e, abs_url)
		return result.content, result.status_code

	def handle_urlfetch_error(self, e, abs_url):
		if isinstance(e, urlfetch.InvalidURLError):
			msg = "The Twiddla library attempted to fetch an invalid URL (%r).	This is likely due to a bug in the Twiddla Python bindings.	Please let us know at info@twiddla.com." % (abs_url, )
		elif isinstance(e, urlfetch.DownloadError):
			msg = "There were a problem retrieving data from Twiddla."
		elif isinstance(e, urlfetch.ResponseTooLargeError):
			msg = "There was a problem receiving all of your data from Twiddla.	This is likely due to a bug in Twiddla.	Please let us know at info@twiddla.com."
		else:
			msg = "Unexpected error communicating with Twiddla.	If this problem persists, let us know at info@twiddla.com."
		msg = textwrap.fill(msg) + "\n\n(Network error: " + str(e) + ")"
		raise Exception(msg)

	def urllib2_request(self, meth, abs_url, headers, params):
		args = {}
		if meth == 'get':
			abs_url = '%s?%s' % (abs_url, self.encode(params))
			req = urllib2.Request(abs_url, None, headers)
		elif meth == 'post':
			body = self.encode(params)
			req = urllib2.Request(abs_url, body, headers)
		elif meth == 'delete':
			abs_url = '%s?%s' % (abs_url, self.encode(params))
			req = urllib2.Request(abs_url, None, headers)
			req.get_method = lambda: 'DELETE'
		else:
			raise Exception('Unrecognized HTTP method %r.	This may indicate a bug in the Twiddla bindings.	Please contact info@twiddla.com for assistance.' % (meth, ))

		try:
			response = urllib2.urlopen(req)
			rbody = response.read()
			rcode = response.code
		except urllib2.HTTPError, e:
			rcode = e.code
			rbody = e.read()
		except (urllib2.URLError, ValueError), e:
			self.handle_urllib2_error(e, abs_url)
		return rbody, rcode

	def handle_urllib2_error(self, e, abs_url):
		msg = "Unexpected error communicating with Twiddla.	If this problem persists, let us know at info@twiddla.com."
		msg = textwrap.fill(msg) + "\n\n(Network error: " + str(e) + ")"
		raise Exception(msg)
















class APICaller(object):
	def __init__(self, username=None, password=None):
		self.username = username
		self.password = password
		self.message = ''
		self.html = ''



	@classmethod
	def _utf8(cls, value):
		if isinstance(value, unicode):
			return value.encode('utf-8')
		else:
			return value

	@classmethod
	def encode_dict(cls, stk, key, dictvalue):
		n = {}
		for k, v in dictvalue.iteritems():
			k = cls._utf8(k)
			v = cls._utf8(v)
			n["%s[%s]" % (key, k)] = v
		stk.extend(cls._encode_inner(n))

	@classmethod
	def encode_datetime(cls, stk, key, dttime):
		utc_timestamp = int(time.mktime(dttime.timetuple()))
		stk.append((key, utc_timestamp))

	@classmethod
	def encode_none(cls, stk, k, v):
		pass # do not include None-valued params in request

	@classmethod
	def _encode_inner(cls, d):
		"""
		We want post vars of form:
		{'foo': 'bar', 'nested': {'a': 'b', 'c': 'd'}}
		to become:
		foo=bar&nested[a]=b&nested[c]=d
		"""
		# special case value encoding
		ENCODERS = {
			dict: cls.encode_dict,
			datetime.datetime: cls.encode_datetime,
			types.NoneType: cls.encode_none,
		}

		stk = []
		for key, value in d.iteritems():
			key = cls._utf8(key)
			try:
					encoder = ENCODERS[value.__class__]
					encoder(stk, key, value)
			except KeyError:
				# don't need special encoding
				value = cls._utf8(value)
				stk.append((key, value))
		return stk

	@classmethod
	def _objects_to_ids(cls, d):
		if isinstance(d, APIResource):
			return d.id
		elif isinstance(d, dict):
			res = {}
			for k, v in d.iteritems():
				res[k] = cls._objects_to_ids(v)
			return res
		else:
			return d

	@classmethod
	def encode(cls, d):
		"""
		Internal: encode a string for url representation
		"""
		return urllib.urlencode(cls._encode_inner(d))

	def call(self, url, params={}):
		"""
		Mechanism for issuing an API call
		"""
		
		if self.username is None or self.password is None:
			self.message = 'No user/pass provided.'
			return False

		params = params.copy()
		params['username'] = self.username
		params['password'] = self.password
		meth = 'post'
		headers = {}

		if _httplib == 'requests':
			rbody, rcode = self.requests_request(meth, url, headers, params)
		elif _httplib == 'pycurl':
			rbody, rcode = self.pycurl_request(meth, url, headers, params)
		elif _httplib == 'urlfetch':
			rbody, rcode = self.urlfetch_request(meth, url, headers, params)
		elif _httplib == 'urllib2':
			rbody, rcode = self.urllib2_request(meth, url, headers, params)
		else:
			rbody, rcode = self.requests_request(meth, url, headers, params)
			#raise Exception("Can't find _httplib")

		self.html = rbody
		if not (200 == rcode):
			self.message = rbody
			return False
			
		if (rbody.startswith('-1')):
			self.message = rbody
			return False
			
		return True

	def pycurl_request(self, meth, abs_url, headers, params):
		s = StringIO.StringIO()
		curl = pycurl.Curl()

		meth = meth.lower()
		if meth == 'get':
			curl.setopt(pycurl.HTTPGET, 1)
			# TODO: maybe be a bit less manual here
			if params:
					abs_url = '%s?%s' % (abs_url, self.encode(params))
		elif meth == 'post':
			curl.setopt(pycurl.POST, 1)
			curl.setopt(pycurl.POSTFIELDS, self.encode(params))
		elif meth == 'delete':
			curl.setopt(pycurl.CUSTOMREQUEST, 'DELETE')
			if params:
					abs_url = '%s?%s' % (abs_url, self.encode(params))
		else:
			raise Exception('Unrecognized HTTP method %r.	This may indicate a bug in the Twiddla bindings.	Please contact info@twiddla.com for assistance.' % (meth, ))

		# pycurl doesn't like unicode URLs
		abs_url = self._utf8(abs_url)
		curl.setopt(pycurl.URL, abs_url)
		curl.setopt(pycurl.WRITEFUNCTION, s.write)
		curl.setopt(pycurl.NOSIGNAL, 1)
		curl.setopt(pycurl.CONNECTTIMEOUT, 30)
		curl.setopt(pycurl.TIMEOUT, 80)
		curl.setopt(pycurl.HTTPHEADER, ['%s: %s' % (k, v) for k, v in headers.iteritems()])
		if verify_ssl_certs:
			curl.setopt(pycurl.CAINFO, os.path.join(os.path.dirname(__file__), 'data/ca-certificates.crt'))
		else:
			curl.setopt(pycurl.SSL_VERIFYHOST, False)

		try:
			curl.perform()
		except pycurl.error, e:
			self.handle_pycurl_error(e)
		rbody = s.getvalue()
		rcode = curl.getinfo(pycurl.RESPONSE_CODE)
		return rbody, rcode

	def handle_pycurl_error(self, e):
		if e[0] in [pycurl.E_COULDNT_CONNECT,
								pycurl.E_COULDNT_RESOLVE_HOST,
								pycurl.E_OPERATION_TIMEOUTED]:
			msg = "Could not connect to Twiddla (%s).	Please check your internet connection and try again." % (api_base, )
		elif e[0] == pycurl.E_SSL_CACERT or e[0] == pycurl.E_SSL_PEER_CERTIFICATE:
			msg = "Could not verify Twiddla's SSL certificate.	Please make sure that your network is not intercepting certificates.	(Try going to %s in your browser.)	If this problem persists, let us know at info@twiddla.com." % (api_base, )
		else:
			msg = "Unexpected error communicating with Twiddla.	If this problem persists, let us know at info@twiddla.com."
		msg = textwrap.fill(msg) + "\n\n(Network error: " + e[1] + ")"
		raise Exception(msg)

	def urlfetch_request(self, meth, abs_url, headers, params):
		args = {}
		if meth == 'post':
			args['payload'] = self.encode(params)
		elif meth == 'get' or meth == 'delete':
			abs_url = '%s?%s' % (abs_url, self.encode(params))
		else:
			raise Exception('Unrecognized HTTP method %r.	This may indicate a bug in the Twiddla bindings.	Please contact info@twiddla.com for assistance.' % (meth, ))
		args['url'] = abs_url
		args['method'] = meth
		args['headers'] = headers
		args['validate_certificate'] = verify_ssl_certs
		# GAE requests time out after 60 seconds, so make sure we leave
		# some time for the application to handle a slow Twiddla
		args['deadline'] = 55

		try:
			result = urlfetch.fetch(**args)
		except urlfetch.Error, e:
			self.handle_urlfetch_error(e, abs_url)
		return result.content, result.status_code

	def handle_urlfetch_error(self, e, abs_url):
		if isinstance(e, urlfetch.InvalidURLError):
			msg = "The Twiddla library attempted to fetch an invalid URL (%r).	This is likely due to a bug in the Twiddla Python bindings.	Please let us know at info@twiddla.com." % (abs_url, )
		elif isinstance(e, urlfetch.DownloadError):
			msg = "There were a problem retrieving data from Twiddla."
		elif isinstance(e, urlfetch.ResponseTooLargeError):
			msg = "There was a problem receiving all of your data from Twiddla.	This is likely due to a bug in Twiddla.	Please let us know at info@twiddla.com."
		else:
			msg = "Unexpected error communicating with Twiddla.	If this problem persists, let us know at info@twiddla.com."
		msg = textwrap.fill(msg) + "\n\n(Network error: " + str(e) + ")"
		raise Exception(msg)

	def urllib2_request(self, meth, abs_url, headers, params):
		args = {}
		if meth == 'get':
			abs_url = '%s?%s' % (abs_url, self.encode(params))
			req = urllib2.Request(abs_url, None, headers)
		elif meth == 'post':
			body = self.encode(params)
			req = urllib2.Request(abs_url, body, headers)
		elif meth == 'delete':
			abs_url = '%s?%s' % (abs_url, self.encode(params))
			req = urllib2.Request(abs_url, None, headers)
			req.get_method = lambda: 'DELETE'
		else:
			raise Exception('Unrecognized HTTP method %r.	This may indicate a bug in the Twiddla bindings.	Please contact info@twiddla.com for assistance.' % (meth, ))

		try:
			response = urllib2.urlopen(req)
			rbody = response.read()
			rcode = response.code
		except urllib2.HTTPError, e:
			rcode = e.code
			rbody = e.read()
		except (urllib2.URLError, ValueError), e:
			self.handle_urllib2_error(e, abs_url)
		return rbody, rcode

	def handle_urllib2_error(self, e, abs_url):
		msg = "Unexpected error communicating with Twiddla.	If this problem persists, let us know at info@twiddla.com."
		msg = textwrap.fill(msg) + "\n\n(Network error: " + str(e) + ")"
		raise Exception(msg)











class TwiddlaHelper(object):
	def __init__(self, username=None, password=None):
		self.username = username
		self.password = password
		self.caller = APICaller(username, password)

	def CreateMeeting(self, meetingtitle=None, meetingpassword=None, url=None):
		"""
		Create a new Twiddla Meeting/Whiteboard/Session
		
		Returns the SessionID of the newly created Meeting
		"""
		params = {
			'meetingtitle': meetingtitle,
			'meetingpassword': meetingpassword,
			'url': url
			}
		#self.AppendCredentials(params)
		
		if (self.caller.call("https://www.twiddla.com/new.aspx", params)):
			return int(self.caller.html)
		else:
			raise Exception(self.caller.html)
	
	def CreateUser(self, newusername, newpassword, displayname, email):
		"""
		Create a new Twiddla User.  
		(You should probably have one of these for every user account on your own site)
		
		Returns the UserID of the newly created User
		"""
		params = {
			'newusername': newusername,
			'newpassword': newpassword,
			'displayname': displayname,
			'email': email
			}
		#self.AppendCredentials(params)
		
		if (self.caller.call("https://www.twiddla.com/API/CreateUser.aspx", params)):
			return int(self.caller.html)
		else:
			raise Exception(self.caller.html)
	
	def ListActive(self, format="csv"):
		"""
		Returns a list of active Meetings/Whiteboards/Sessions.  
		
		Valid formats are "csv" and "xml"
		"""
		params = {
			'format': format
			}
		#self.AppendCredentials(params)
		
		if (self.caller.call("https://www.twiddla.com/API/ListActive.aspx", params)):
			return int(self.caller.html)
		else:
			raise Exception(self.caller.html)
	
	def ListSnapshots(self, format="csv", sessionid=None):
		"""
		Returns a list of Snapshots, optionally filtered by sessionid.  
		
		Valid formats are "csv" and "xml"
		"""
		params = {
			'format': format
			}
		#self.AppendCredentials(params)
		
		if (self.caller.call("https://www.twiddla.com/API/ListSnapshots.aspx", params)):
			return int(self.caller.html)
		else:
			raise Exception(self.caller.html)
