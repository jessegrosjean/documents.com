import os
import re
import sys
import zlib
import hashlib
import logging
import datetime
import wsgiref.handlers

from django.utils import simplejson
from diff_match_patch import diff_match_patch

from google.appengine import runtime
from google.appengine.ext import db
from google.appengine.api import users
from google.appengine.ext import webapp
from google.appengine.api import quota
from google.appengine.api import memcache
from google.appengine.ext.webapp import util
from google.appengine.ext.webapp import template
from google.appengine.api.datastore_types import Blob 

admin = "jesse@hogbaysoftware.com"
dmp = diff_match_patch()

#def baseN(num,b):
#	return ((num == 0) and  "0" ) or ( baseN(num // b, b).lstrip("0") + "0123456789abcdefghijklmnopqrstuvwxyz"[num % b])
#baseN(1023439232, 32) = 
#string.atoi('ug0sc0', 32) = 1023439232
#
# Requirements for future datastore release
# Get document, account, and document body in single, so extra query to fetch body is no longer needed.
# accounts should be keyed by user_id, no query needed.
# avoid loading accounts, don't track cpu time, storage for account can be computed later.
# Move owner field to document
# Remoe documents from account entity group, they should stand on own.
# Possible to get rid of account object? That would save query on every load.
#

#
# Models
#

def list_union(l1, l2):
	return l1 + filter(lambda x: x not in l1, l2)
	
def list_minus(l1, l2):
	return filter(lambda x: x not in l2, l1)

def list_with_user_id(l, user_id):
	if not l:
		l = []
	if not user_id in l:
		l.append(user_id)
	return l

class Account(db.Model):
	user = db.UserProperty(required=True)
	user_id = db.StringProperty()
	model_version = db.IntegerProperty(default=0)
	last_paid = db.DateTimeProperty()

	@classmethod
	def get_account_for_user(cls, user):
		if user:
			account_by_user_id_query.bind(user.user_id())
			accounts = account_by_user_id_query.fetch(2)
			account = None

			if (len(accounts) > 1):
				logging.error("Found multiple accounts with id %s", user.user_id())
				account = accounts[0]
			elif len(accounts) == 1:
				account = accounts[0]

			if account:
				if account.user == user: # else user email changed, so update account
					return account
			else:
				account = account_by_user_query.bind(user)
				account = account_by_user_query.get()
				
			if account == None:
				account = Account(user=user, user_id=user.user_id())
				account.put()
				if not account.user_id:
					# Hack, and still doesn't totally work user.user_id() isn't set until user stored in DB.
					# But even doing this, on dev server at least, user.user_id() gets loaded, but setting
					# account.user_id doesn't seem to work. It remains None.
					account = account_by_user_query.get()
					account.user_id = account.user.user_id()
					account.put()
			else:
				account.user = user
				account.user_id = user.user_id()
				account.put()
				
			return account
		return None

	def __eq__(self, other):
		return self.user == other.user if isinstance(other, Account) else False
		
	def get_documents(self):
		documents_query.bind(self.user.user_id(), False)
		return documents_query

class CompressedTextProperty(db.TextProperty):
	def get_value_for_datastore(self, model_instance): 
		value = super(CompressedTextProperty, self).get_value_for_datastore(model_instance)
		if value:
			value = value.encode("utf-8")
			return Blob(zlib.compress(value, 9)) 
		else:
			return None
	
	def make_value_from_datastore(self, value): 
		if value is None: 
			return None 
		return unicode(zlib.decompress(value), "utf-8")

class Document(db.Model):
	version = db.IntegerProperty(required=True)
	last_revision = db.DateTimeProperty(required=True, auto_now_add=True)
	unamed_revisions_count = db.IntegerProperty(required=True, default=0)
	name = db.StringProperty(required=True, default="Untitled")
	name_version = db.IntegerProperty(required=True, default=0)
	size = db.IntegerProperty(required=True, default=0)
	created = db.DateTimeProperty(required=True, auto_now_add=True)
	modified = db.DateTimeProperty(required=True, auto_now=True)
	tags = db.StringListProperty()
	user_ids = db.StringListProperty(required=True)
	deleted = db.BooleanProperty(required=True, default=False)
	body = None
	
	def id_string(self):
		return "%s-%s" % (self.parent_key().id(), self.key().id())
	
	def uri(self):
		return "/documents/%s" % self.id_string()

	def get_body(self):
		if not self.body:
			body_query.bind(self)
			self.body = body_query.get()
		return self.body
	
	def to_index_dictionary(self):
		return { 'id': self.id_string(), 'version': self.version, 'name': self.name }

	def to_document_dictionary(self):
		return { 'id': self.id_string(), 'name': self.name, 'version': self.version, 'created': str(self.created), 'modified': str(self.modified), 'tags' : self.tags, 'user_ids' : self.user_ids, 'content': self.get_body().content }
		
	def create_revision(self, user_account, document_account, content, levenshtein, conflicts=None, revision_name=None):
		key_date = datetime.datetime.utcnow()
		
		if self.last_revision >= key_date:
			key_date = self.last_revision + datetime.timedelta(seconds=1)

		if key_date.microsecond != 0:
			key_date = key_date + datetime.timedelta(microseconds=-key_date.microsecond)

		revision = Revision(key_name="k:%s" % key_date.isoformat('_').replace(':', '.'), parent=self, account=user_account, name=self.name, user_ids=self.user_ids, tags=self.tags, content=content, levenshtein=levenshtein, revision_name=revision_name)

		if conflicts != None and len(conflicts) > 0:
			revision.conflicts = ''.join(conflicts)
			revision.conflicts_resolved = False

		if not revision.is_named():
			self.unamed_revisions_count += 1
			
		self.size += revision.size()
		self.last_revision = key_date

		return revision
		
	def delete_revision(self, revision, document_account):
		if not revision.is_named():
			self.unamed_revisions_count -= 1
		self.size -= revision.size()			
	
	def clearMemcache(self, clear_ids=[]):
		clear_ids.extend(self.user_ids)
		memcache.delete_multi(clear_ids)

class Body(db.Model):
	content = db.TextProperty()
	content_size = db.IntegerProperty()	

class Revision(db.Model):
	account = db.ReferenceProperty(Account, required=True)
	levenshtein = db.IntegerProperty(required=True, default=0)
	name = db.StringProperty()
	tags = db.StringListProperty()
	user_ids = db.StringListProperty()
	content = CompressedTextProperty()
	conflicts = CompressedTextProperty()
	conflicts_resolved = db.BooleanProperty(default=None)
	revision_name = db.StringProperty(default="")
		
	def is_valid(self):
		return self.parent() != None

	def is_named(self):
		return self.revision_name != None and len(self.revision_name) > 0
		
	def uri(self):
		return "/documents/%s/revision/%i" % (self.parent().id_string(), self.key().name()[2:])
		
	def to_revision_dictionary(self):
		return { 'id' : self.key().name()[2:], 'document_id' : self.parent().id_string(), 'name': self.name, 'tags' : self.tags, 'user_ids' : self.user_ids, 'content': self.content, 'conflicts' : self.conflicts, 'conflicts_resolved' : self.conflicts_resolved }
		
	def size(self):
		if self.conflicts:
			return len(self.content) + len(self.conflicts)
		else:
			return len(self.content)

#
# Queries
#

account_by_user_id_query = Account.gql("WHERE user_id = :1", None)
account_by_user_query = Account.gql("WHERE user = :1", None)
documents_query = Document.gql("WHERE user_ids = :1 AND deleted = :2 ORDER BY name", None, False)
documents_query_with_tag = Document.gql("WHERE user_ids = :1 AND deleted = :2 AND tags = :3 ORDER BY name", None, False, None)
body_query = Body.gql("WHERE ANCESTOR IS :1", None)
revisions_with_unresolved_conflicts_query = Revision.gql("WHERE account = :1 AND conflicts_resolved = :2 ORDER BY __key__ DESC", None, False)
revisions_keys_query = db.GqlQuery("SELECT __key__ FROM Revision WHERE ANCESTOR IS :1 ORDER BY __key__ DESC", None)

#
# Controllers
#
	
def is_development_server():
	return os.environ['SERVER_SOFTWARE'].startswith('Dev')
	
def stop_processing(*a, **kw):
	pass

def write_json_response(response, json):
	response.headers['Content-Type'] = 'application/json'
	response.out.write(simplejson.dumps(json))
	
def require_account(f):	
	def g(*args, **kwargs):
		try:
			handler = args[0]
		
			user_account = Account.get_account_for_user(users.get_current_user())
			if user_account == None:
				handler.error(401)
				return stop_processing
		
			handler.response.headers['Account-Email'] = str(user_account.user.email())
			handler.response.headers['Account-ID'] = str(user_account.user.user_id())
			handler.response.headers['Server-Version'] = "2"
			new_args = (handler, user_account) + args[1:]
		
			return f(*new_args, **kwargs)
		except (db.TransactionFailedError, runtime.DeadlineExceededError):
			handler.response.headers['Retry-After'] = "1" # App engine should handle it, don't worry about backoff.
			handler.response.clear()
			handler.response.set_status(503)
			handler.response.out.write("Please try again.")
			logging.error("Service Unavailable %s %s" % (handler.request.url, sys.exc_info()[:2]))
			return stop_processing
	return g

def require_document(f):
	@require_account
	def g(*args, **kwargs):
		handler = args[0]
		user_account = args[1]
		document_account_id = args[2]
		document_id = args[3]
		document, document_account = get_document_and_document_account(handler, user_account, document_account_id, document_id)
		if document == None or document.deleted or document_account == None:
			return stop_processing 
			
		new_args = (handler, user_account, document_account, document) + args[4:]
		return f(*new_args, **kwargs)
	return g

def require_revision(f):
	@require_document
	def g(*args, **kwargs):
		handler = args[0]
		user_account = args[1]
		document_account = args[2]
		document = args[3]
		revision_id = 'k:%s' % args[4]
		revision = Revision.get_by_key_name(revision_id, document)
		
		if not revision:
			handler.error(401)
			return stop_processing 

		new_args = (handler, user_account, document_account, document, revision) + args[5:]
		return f(*new_args, **kwargs)
	return g

def get_document_and_document_account(handler, user_account, document_account_id, document_id):
	try:
		document_account, document = db.get([db.Key.from_path('Account', int(document_account_id)), db.Key.from_path('Account', int(document_account_id), 'Document', int(document_id))])
	except db.BadKeyError:
		document = None
		document_account = None

	if document == None or document.deleted or document_account == None:
		handler.error(404)
		return None, None
	elif not (document_account == user_account or user_account.user.user_id() in document.user_ids or users.is_current_user_admin()):
		handler.error(401)
		return None, None

	return document, document_account

def render(file, template_values={}):
	path = os.path.join(os.path.dirname(__file__) + '/templates', file)
	if (os.path.exists(path)):
		return template.render(path, template_values)
	else:
		return False

newline_re = re.compile(u'\r\n|\r')
illegal_re = re.compile(u'[\x00-\x08\x0B-\x0C\x0E-\x1F\x7F]')

def standardize_line_endings_and_characters(text):
	text = newline_re.subn('\n', text)[0]
	text = illegal_re.subn('', text)[0]
	return text

def validate_name(name):
	if name:
		name = standardize_line_endings_and_characters(re.split(r"(\r\n|\r|\n)", name, 1)[0])
		l = len(name)
		if l == 0:
			name = 'Untitled'
		elif l > 256:
			name = name[0:256]
	return name

class BaseHandler(webapp.RequestHandler):
	def head(self, *args):
		self.get(*args)
		self.response.clear()

	def handle_exception(self, exception, debug_mode):
		webapp.RequestHandler.handle_exception(self, exception, debug_mode)

class AdminHandler(BaseHandler):
	def get(self):
		if users.is_current_user_admin():
			account_id = self.request.get("account_id", None)
			account_by_id = None

			if account_id:
				account_by_id = Account.get(db.Key.from_path('Account', int(account_id)))				

			account_email = self.request.get("account_email", None)
			account_by_email = None

			if account_email:
				account_by_email = Account.get_account_for_user(users.User(account_email))			
				
			self.response.out.write(render("Admin.html", { 'account_by_id' : account_by_id, 'account_by_email' : account_by_email, 'title' : "Admin", 'size_accounts' : Account.gql("ORDER BY documents_size DESC").fetch(100), 'cpu_accounts' : Account.gql("ORDER BY documents_cpu DESC").fetch(100) } ))
		else:
			self.redirect(users.create_login_url("/admin"), False)

class ClientHandler(BaseHandler):
	def get(self):
		if self.request.path.find("/documents/") == 0:
			user = users.get_current_user()
			if user:
				self.response.out.write(render("Documents.html", { 'user_name' : user.email(), 'logout_url' : users.create_logout_url("/") } ))		
			else:
				self.redirect(users.create_login_url("/documents/"), False)
		else:
			self.redirect("/documents/", True)
		
class DocumentsHandler(BaseHandler):
	@require_account
	def get(self, account):
		cache_key = account.user.user_id()
		requestEtag = self.request.headers.get('If-None-Match', None)
		serverEtag = memcache.get(cache_key)
		
		if serverEtag != None and (requestEtag == serverEtag):
			self.response.headers['Etag'] = serverEtag
			self.response.set_status(304)
		else:
			document_dicts = []
			for document in account.get_documents():
				document_dicts.append(document.to_index_dictionary())			
			json_response = simplejson.dumps(document_dicts)

			if not serverEtag:
				serverEtag = hashlib.md5(json_response).hexdigest()
				memcache.set(cache_key, serverEtag)

			self.response.headers['Etag'] = serverEtag
			self.response.headers['Content-Type'] = 'application/json'
			self.response.out.write(json_response)

	@require_account
	def post(self, account):
		jsonDocument = simplejson.loads(self.request.body)
		name = validate_name(jsonDocument.get('name', None))
		tags = jsonDocument.get('tags', [])
		user_ids = list_with_user_id(jsonDocument.get('user_ids'), account.user.user_id())
		content = standardize_line_endings_and_characters(jsonDocument.get('content', ''))

		def create_document_txn():
			document = Document(parent=account, version=0, name=name, tags=tags, user_ids=user_ids, size=len(content))
			document.put()
			revision = document.create_revision(account, account, content, sys.maxint)
			body = Body(parent=document, content=content, content_size=len(content))
			db.put([body, revision, account])
			return document
	
		document = db.run_in_transaction(create_document_txn)
		document.clearMemcache()
		
		self.response.set_status(201)
		self.response.headers.add_header("Location", document.uri())
		write_json_response(self.response, document.to_document_dictionary())
		
def delta_update_document_txn(handler, user_account, document_account_id, document_id, version, name, patches, tags_added, tags_removed, user_ids_added, user_ids_removed, revision_name=None, always_return_content=False):
	document, document_account = get_document_and_document_account(handler, user_account, document_account_id, document_id)

	if document == None or document_account == None:
		return None

	document.version = document.version + 1
	puts = [document, document_account]
	levenshtein = (len(tags_added) + len(tags_removed) + len(user_ids_added) + len(user_ids_removed)) * 10
	conflicts = []

	if (name != None and name != document.name):
		if version >= document.name_version:
			document.name = name
			document.name_version = document.version;
			levenshtein += 10

	if len(tags_added) > 0: document.tags = list_union(document.tags, tags_added)
	if len(tags_removed) > 0: document.tags = list_minus(document.tags, tags_removed)
	if len(user_ids_added) > 0: document.user_ids = list_union(document.user_ids, user_ids_added)
	if len(user_ids_removed) > 0: document.user_ids = list_minus(document.user_ids, user_ids_removed)

	document_user_id = document_account.user.user_id()
	if not document_user_id in document.user_ids:
		document.user_ids.append(document_user_id)
	
	if (patches != None):
		logging.info("Patches: %s" % patches) # store in logs for debug
		dmp.Match_Threshold = 0.75
		patches = dmp.patch_fromText(patches)
		body = document.get_body()
		content, results, results_patches = dmp.patch_apply(patches, body.content)
		content = standardize_line_endings_and_characters(content)
		document.size -= body.content_size
		body.content = content
		body.content_size = len(content)
		document.size += body.content_size
		puts.append(body)

		index = 0
		for each in results:
			if each == False:
				conflicts.append(dmp.patch_toText([results_patches[index]]))
			else:
				levenshtein += dmp.diff_levenshtein(results_patches[index].diffs)
			index += 1

	revision = document.create_revision(user_account, document_account, document.get_body().content, levenshtein, conflicts, revision_name)
	puts.append(revision)

	db.put(puts)
	document.clearMemcache(user_ids_removed)
	handler.response.headers['Etag'] = str(document.version)

	if version != document.version - 1 or always_return_content:
		jsonResults = document.to_document_dictionary()
		if revision.conflicts_resolved == False:
			jsonResults["conflicts"] = revision.conflicts
		return jsonResults
	else:
		return document.to_index_dictionary()
		
class DocumentHandler(BaseHandler):
	@require_document
	def get(self, user_account, document_account, document):
		requestEtag = self.request.headers.get('If-None-Match', None)
		serverEtag = str(document.version)
		self.response.headers['Etag'] = serverEtag
		
		if requestEtag == serverEtag:
			self.response.set_status(304)
		else:
			write_json_response(self.response, document.to_document_dictionary())
	
	def post(self, account_id, document_id):
		method = self.request.headers.get('X-HTTP-Method-Override')
		if (method == "PUT"):
			self.put(account_id, document_id)
		elif (method == "DELETE"):
			self.delete(account_id, document_id)
		else:
			self.error(405)

	@require_account
	def put(self, user_account, document_account_id, document_id):
		jsonDocument = simplejson.loads(self.request.body)
		version = jsonDocument.get('version')
		version = None if version == None else int(version)
		name = validate_name(jsonDocument.get('name', None))
		patches = jsonDocument.get('patches', None)
		tags_added = jsonDocument.get('tags_added')
		tags_added = [] if tags_added == None else tags_added
		tags_removed = jsonDocument.get('tags_removed')
		tags_removed = [] if tags_removed == None else tags_removed
		user_ids_added = jsonDocument.get('user_ids_added')
		user_ids_added = [] if user_ids_added == None else user_ids_added
		user_ids_removed = jsonDocument.get('user_ids_removed')
		user_ids_removed = [] if user_ids_removed == None else user_ids_removed
		results = db.run_in_transaction(delta_update_document_txn, self, user_account, document_account_id, document_id, version, name, patches, tags_added, tags_removed, user_ids_added, user_ids_removed)
		if results:
			write_json_response(self.response, results)
			
	@require_account
	def delete(self, user_account, document_account_id, document_id):
		version = self.request.get('version', None)
		version = None if version == None else int(version)
				
		if version == None:
			self.error(400)
			return
		
		def delete_document_txn():
			document, document_account = get_document_and_document_account(self, user_account, document_account_id, document_id)
			if document == None or document_account == None:
				raise ValueError, "Document doesn't exist or you don't have access to delete document"
			if version != document.version:
				self.error(409)
				raise ValueError, "Version does not match document version"

			document.deleted = True
			db.put([document, document_account])
			return document

		try:
			document = db.run_in_transaction(delete_document_txn)
			document.clearMemcache()
		except ValueError:
			pass

class DocumentRevisionsHandler(BaseHandler):
	@require_document
	def get(self, user_account, document_account, document):
		revisions_keys_query.bind(document)
		revision_keys = []
		for revision_key in revisions_keys_query.fetch(1000):
			revision_keys.append(revision_key.name()[2:])
		write_json_response(self.response, revision_keys)
		
class DocumentRevisionHandler(BaseHandler):
	@require_revision
	def get(self, user_account, document_account, document, revision):
		write_json_response(self.response, revision.to_revision_dictionary())

	def post(self, account_id, document_id, revision_id):
		method = self.request.headers.get('X-HTTP-Method-Override')
		if (method == "PUT"):
			self.put(account_id, document_id, revision_id)
		elif (method == "DELETE"):
			self.delete(account_id, document_id, revision_id)
		else:
			self.error(405)

	@require_revision
	def put(self, user_account, document_account, document, revision):
		revision.conflicts_resolved = simplejson.loads(self.request.body).get('conflicts_resolved', False)
		revision.put()

	@require_revision
	def delete(self, user_account, document_account, document, revision):
		document.delete_revision(revision, document_account) # BAD, untested code, need to rethink
		
		def delete_revision_txn():
			document.deleted = True			
			db.put([document, document_account])
			return document

		try:
			document = db.run_in_transaction(delete_document_txn)
			document.clearMemcache()
		except ValueError:
			pass

class ConflictsHandler(BaseHandler):
	@require_account
	def get(self, account):
		conflict_dicts = []
		revisions_with_unresolved_conflicts_query.bind(account, False)
		for revision in revisions_with_unresolved_conflicts_query.fetch(10):
			if revision.is_valid():
				conflict_dicts.append(revision.to_revision_dictionary())
		write_json_response(self.response, conflict_dicts)

class DocumentsCronHandler(BaseHandler):
	def get(self):
		def delete_document_txn(document):
			to_delete = []
			revisions = db.GqlQuery("SELECT __key__ FROM Revision WHERE ANCESTOR IS :document", document=document).fetch(10)
			to_delete.extend(revisions)
			if (len(revisions) < 5):
				to_delete.append(document)
				account = document.parent()
				if account:
					db.put(account)
				body = document.get_body()
				if body:
					to_delete.append(body)
			db.delete(to_delete)

		for each in Document.gql("WHERE deleted = True AND modified < :1", datetime.datetime.today() - datetime.timedelta(days=7)).fetch(5):
			db.run_in_transaction(delete_document_txn, each)
		
		return

class PrintUserHandler(BaseHandler):
	def get(self):
		user = users.get_current_user()
		if user:
			self.response.headers['Content-Type'] = 'text/plain'
			self.response.out.write('Hello, ' + user.nickname() + ' id: ' + user.user_id())
		else:
			self.redirect(users.create_login_url(self.request.uri))

def main():
	application = webapp.WSGIApplication([
		('/admin/?', AdminHandler),
		('/documents', ClientHandler),
		('/documents/', ClientHandler),
		('/v1/documents/?', DocumentsHandler),
		('/v1/documents/conflicts/?', ConflictsHandler),
		('/v1/documents/([0-9]+)-([0-9]+)/?', DocumentHandler),
		('/v1/documents/([0-9]+)-([0-9]+)/revisions/?', DocumentRevisionsHandler),
		('/v1/documents/([0-9]+)-([0-9]+)/revisions/(.+)/?', DocumentRevisionHandler),
		('/v1/cron', DocumentsCronHandler),
		('/v1/printuser/?', PrintUserHandler),
		], debug=False)
		
	util.run_wsgi_app(application)

if __name__ == '__main__':
	main()