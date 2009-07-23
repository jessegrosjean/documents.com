import os
import re
import logging
import datetime
import operator
import wsgiref.handlers

from django.utils import simplejson
from diff_match_patch import diff_match_patch

from google.appengine import runtime
from google.appengine.ext import db
from google.appengine.api import users
from google.appengine.ext import webapp
from google.appengine.api import quota
from google.appengine.api import memcache
from google.appengine.ext.webapp import template

#
# Models
#

def list_union(l1, l2):
	return l1 + filter(lambda x: x not in l1, l2)
	
def list_minus(l1, l2):
	return filter(lambda x: x not in l2, l1)
	
def list_from_string(string):
	if string:
		return string.split()
	else:
		return []

def user_id_for_user(user):
	if is_development_server():
		return user.email()
	else:
		return user.user_id() # inconsistent on dev server

def list_with_user_id(l, user_id):
	if not user_id in l:
		l.append(user_id)
	return l

class Account(db.Model):
	user = db.UserProperty(required=True)
	user_id = db.StringProperty()
	documents_size = db.IntegerProperty(required=True, default=0)
	documents_cpu = db.IntegerProperty(default=0)

	@classmethod
	def get_account_for_user(cls, user):
		if user:
			account_by_user_id_query.bind(user_id_for_user(user))
			account = account_by_user_id_query.get()

			if account == None:
				account = account_by_user_query.bind(user)
				account = account_by_user_query.get()
				
			if account == None:
				account = Account(user=user, user_id=user_id_for_user(user))
				account.put()
			else:
				account.user = user
				account.user_id = user_id_for_user(user)
				account.put()
			return account
		return None

	def __eq__(self, other):
		return self.user == other.user if isinstance(other, Account) else False
		
	def get_documents(self):
		documents_query.bind(self.user_id, False)
		return documents_query

	def get_edits_with_unresolved_conflicts(self):
		edits_with_unresolved_conflicts_query.bind(self, False)
		return edits_with_unresolved_conflicts_query

class Document(db.Model):
	version = db.IntegerProperty(required=True)
	name = db.StringProperty(required=True, default="Untitled")
	name_version = db.IntegerProperty(required=True, default=0)
	edits_size = db.IntegerProperty(required=True, default=0)
	edits_cache_modulo = db.IntegerProperty(required=True, default=10)
	created = db.DateTimeProperty(required=True, auto_now_add=True)
	modified = db.DateTimeProperty(required=True, auto_now=True)
	tags = db.StringListProperty()
	user_ids = db.StringListProperty(required=True)
	deleted = db.BooleanProperty(required=True, default=False)
	body = None
	
	def id_string(self):
		return "%s-%s" % (self.parent_key().id(), self.key().id())
				
	def tags_string(self):
		if len(self.tags) > 0:
			return ' '.join(self.tags)
		else:
			return ""

	def user_ids_string(self):
		if len(self.user_ids) > 0:
			return ' '.join(self.user_ids)
		else:
			return ""
	
	def uri(self):
		return "/documents/%s" % self.id_string()

	def get_body(self):
		if not self.body:
			body_query.bind(self)
			self.body = body_query.get()
		return self.body
		
	def get_edits(self, start, end):
		edits_query.bind(document=self, start=start, end=end)
		return edits_query.fetch((end - start) + 1)

	def get_edits_in_json_read_form(self, start, end):
		edits = {}

		name = None
		tags_added = []
		tags_removed = []
		user_ids_added = []
		user_ids_removed = []
		patches = []
		
		for edit in self.get_edits(start, end):
			edits["version"] = edit.version
			 
			if edit.patches:
				patches.append(edit.patches)

			if len(edit.tags_added) > 0:
				tags_added = list_union(tags_added, edit.tags_added)
				tags_removed = list_minus(tags_removed, edit.tags_added)

			if len(edit.tags_removed) > 0:
				tags_removed = list_union(tags_removed, edit.tags_removed)
				tags_added = list_minus(tags_added, edit.tags_removed)

			if len(edit.user_ids_added) > 0:
				user_ids_added = list_union(user_ids_added, edit.user_ids_added)
				user_ids_removed = list_minus(user_ids_removed, edit.user_ids_added)

			if len(edit.user_ids_removed) > 0:
				user_ids_removed = list_union(user_ids_removed, edit.user_ids_removed)
				user_ids_added = list_minus(user_ids_added, edit.user_ids_removed)
								
			if edit.new_name:
				name = edit.new_name

		if name: edits["name"] = name
		if len(tags_added) > 0: edits["tags_added"] = tags_added
		if len(tags_removed) > 0: edits["tags_removed"] = tags_removed
		if len(user_ids_added) > 0: edits["user_ids_added"] = user_ids_added
		if len(user_ids_removed) > 0: edits["user_ids_removed"] = user_ids_removed
		if len(patches) > 0: edits["patches"] = ''.join(patches)
		return edits
	
	def to_index_dictionary(self):
		return { 'id': self.id_string(), 'version': self.version, 'name': self.name }

	def to_document_dictionary(self):
		return { 'owner' : self.parent().user.email(), 'id': self.id_string(), 'name': self.name, 'version': self.version, 'content': self.get_body().content, 'created': str(self.created), 'modified': str(self.modified) }
	
	def clearMemcache(self, clear_ids=[]):
		clear_ids.extend(self.user_ids)
		memcache.delete_multi(clear_ids)

class Body(db.Model):
	content = db.TextProperty()
	content_size = db.IntegerProperty()	

class Edit(db.Model):
	account = db.ReferenceProperty(Account, required=True)
	version = db.IntegerProperty(required=True)
	old_name = db.StringProperty()
	new_name = db.StringProperty()
	tags_added = db.StringListProperty()
	tags_removed = db.StringListProperty()
	user_ids_added = db.StringListProperty()
	user_ids_removed = db.StringListProperty()
	patches = db.TextProperty()
	conflicts = db.TextProperty()
	conflicts_resolved = db.BooleanProperty(default=None)
	created = db.DateTimeProperty(required=True, auto_now_add=True)
	cached_document_name = db.StringProperty()
	cached_document_tags = db.StringListProperty()
	cached_document_user_ids = db.StringListProperty()
	cached_document_content = db.TextProperty()
		
	def is_valid(self):
		return self.parent() != None
		
	def edit_uri(self):
		return "/documents/%s/edits/%i" % (self.parent().id_string(), self.version)

	def version_uri(self):
		return "/documents/%s/versions/%i" % (self.parent().id_string(), self.version)
	
	def has_unresolved_conflicts(self):
		return self.conflicts != None and self.conflicts_resolved == False
		
	def to_conflict_dictionary(self):
		return { 'id' : self.parent().id_string(), 'name' : self.parent().name, 'version' : self.version, 'created' : str(self.created), 'conflicts' : self.conflicts }		
		
	def size(self):
		size = 0;
		if self.old_name: size += len(self.old_name)
		if self.new_name: size += len(self.new_name)
		if self.patches: size += len(self.patches)
		if self.conflicts: size += len(self.conflicts)
		return size
		
	def apply(self, name, tags, user_ids, content, dmp):
		if self.new_name: name = self.new_name
		if len(self.tags_added) > 0: tags = list_union(tags, self.tags_added)
		if len(self.tags_removed) > 0: tags = list_minus(tags, self.tags_removed)
		if len(self.user_ids_added) > 0: user_ids = list_union(user_ids, self.user_ids_added)
		if len(self.user_ids_removed) > 0: user_ids = list_minus(user_ids, self.user_ids_removed)
		if self.patches: content = dmp.patch_apply(dmp.patch_fromText(self.patches.encode('ascii')), content)[0]
		return (name, tags, user_ids, content)
		
	def reverse(self, name, tags, user_ids, content, dmp):
		if self.old_name: name = self.old_name
		if len(self.tags_added) > 0: tags = list_minus(tags, self.tags_added)
		if len(self.tags_removed) > 0: tags = list_union(tags, self.tags_removed)
		if len(self.user_ids_added) > 0: user_ids = list_minus(user_ids, self.user_ids_added)
		if len(self.user_ids_removed) > 0: user_ids = list_union(user_ids, self.user_ids_removed)
		if self.patches: content = dmp.patch_apply(dmp.patch_reverse(dmp.patch_fromText(self.patches.encode('ascii'))), content)[0]
		return (name, tags, user_ids, content)

#
# Queries
#

account_by_user_id_query = Account.gql("WHERE user_id = :1", None)
account_by_user_query = Account.gql("WHERE user = :1", None)
documents_query = Document.gql("WHERE user_ids = :1 AND deleted = :2 ORDER BY name", None, False)
edits_with_unresolved_conflicts_query = Edit.gql("WHERE account = :1 AND conflicts_resolved = :2 ORDER BY created DESC", None, False)
body_query = Body.gql("WHERE ANCESTOR IS :1", None)
edits_query = Edit.gql('WHERE ANCESTOR IS :document AND version >= :start AND version <= :end ORDER BY version ASC', document=None, start=0, end=0)
edit_query = Edit.gql('WHERE ANCESTOR IS :document AND version = :version', document=None, version=0)

#
# Controllers
#

def service_name():
	if os.environ['APPLICATION_ID'].endswith('writeroom'):
		return 'WriteRoom.ws'
	else:
		return 'TaskPaper.ws'
	
def is_development_server():
	return os.environ['SERVER_SOFTWARE'].startswith('Dev')
	
def stop_processing(*a, **kw):
	pass

def write_json_response(response, json):
	response.headers['Content-Type'] = 'application/json'
	response.out.write(simplejson.dumps(json))

def write_deadline_exceeded_response(response, document, account_email):
	logging.error("DeadlineExceededError %s %s" % (document, account_email))
	response.response.clear()
	response.response.set_status(500)
	response.response.out.write("Document %s sync could not be completed in time. If this problem persists the document may be to big. Please delete the document and divide it into two smaller documents." % document)
	
def require_account(f):	
	def g(*a, **kw):
		handler = a[0]

		if is_development_server():
			user_account = Account.get_account_for_user(users.User("test@example.com"))
		else:
			user_account = Account.get_account_for_user(users.get_current_user())
			
		if user_account == None:
			handler.error(401)
			return stop_processing
		new_args = (handler, user_account) + a[1:]
		return f(*new_args, **kw)
	return g

def require_document(f):
	@require_account
	def g(*a, **kw):
		handler = a[0]
		user_account = a[1]
		document_account_id = a[2]
		document_id = a[3]
		document, document_account = get_document_and_document_account(handler, user_account, document_account_id, document_id)
		if document == None or document.deleted or document_account == None:
			return stop_processing 
			
		new_args = (handler, user_account, document_account, document) + a[4:]
		return f(*new_args, **kw)
	return g

def require_document_edits_paging(f):
	@require_document
	def g(*a, **kw):
		handler = a[0]
		user_account = a[1]
		document_account = a[2]
		document = a[3]
		next = None
		previous = None
		
		try:
			start = handler.request.get('start', None)
			end = handler.request.get('end', None)
			page = int(handler.request.get('page', 1))
			if start: start = int(start)
			if end: end = int(end)
		except:
			handler.error(400)
			return stop_processing

		if start == None or end == None:
			page_size = 30
			page_count = (document.version + 1) / float(page_size)
			start = (document.version + 1) - (page * page_size)
			end = start + page_size - 1
			if page_count > page:
				next = page + 1
			if page > 1:
				previous = page - 1
		else:
			if start > document.version or (end < start or end > document.version):
				handler.error(400)
				return stop_processing
				
		new_args = (handler, user_account, document_account, document, start, end, next, previous) + a[4:]
		return f(*new_args, **kw)
	return g

def require_document_edit(f):
	@require_document
	def g(*a, **kw):
		handler = a[0]
		user_account = a[1]
		document_account = a[2]
		document = a[3]
		edit_version = a[4]
		edit_query.bind(document=document, version=int(edit_version))
		edit = edit_query.get()

		if edit == None:
			handler.error(404)
			return stop_processing 

		new_args = (handler, user_account, document_account, document, edit) + a[5:]
		return f(*new_args, **kw)
	return g

def get_document_and_document_account(handler, user_account, document_account_id, document_id):
	try:
		document = Document.get(db.Key.from_path('Account', int(document_account_id), 'Document', int(document_id)))
		if document:
			document_account = document.parent()
	except db.BadKeyError:
		document = None
		document_account = None

	if document == None or document.deleted or document_account == None:
		handler.error(404)
		return None, None
	elif not (document.parent() == user_account or user_account.user.user_id() in document.user_ids):
		handler.error(401)
		return None, None

	return document, document_account

def get_document_version(handler, document, version):
	if version == document.version:
		return (document.name, document.tags, document.user_ids, document.get_body().content)
	elif version > document.version:
		handler.error(404)
		return (None, None, None, None)

	modulo = (version % document.edits_cache_modulo)

	if modulo == 0:
		edit_query.bind(document=document, version=version)
		edit = edit_query.get()
		return (edit.cached_document_name, edit.cached_document_tags, edit.cached_document_user_ids, edit.cached_document_content)
	else:
		base_name = None
		base_tags = None
		base_user_ids = None
		base_content = None
		dmp = diff_match_patch()
		dmp.Match_Threshold = 0.0
		
		if modulo > (document.edits_cache_modulo / 2):
			end_version = (version - modulo) + document.edits_cache_modulo
			edits = document.get_edits(version + 1, end_version)
			edits.reverse()
			first_edit = edits[0]
			if first_edit.version % document.edits_cache_modulo == 0:
				base_name = first_edit.cached_document_name
				base_tags = first_edit.cached_document_tags[:]
				base_user_ids = first_edit.cached_document_user_ids[:]
				base_content = first_edit.cached_document_content
			else:
				base_name = document.name
				base_tags = document.tags[:]
				base_user_ids = document.user_ids[:]
				base_content = document.get_body().content
			calculate_forward = False
		else:
			start_version = (version - modulo)
			edits = document.get_edits(start_version, version)
			first_edit = edits[0]
			base_name = first_edit.cached_document_name
			base_tags = first_edit.cached_document_tags[:]
			base_user_ids = first_edit.cached_document_user_ids[:]
			base_content = first_edit.cached_document_content
			edits = edits[1:]
			calculate_forward = True

		for edit in edits:
			if calculate_forward:
				base_name, base_tags, base_user_ids, base_content = edit.apply(base_name, base_tags, base_user_ids, base_content, dmp)
			else:
				base_name, base_tags, base_user_ids, base_content = edit.reverse(base_name, base_tags, base_user_ids, base_content, dmp)

		return (base_name, base_tags, base_user_ids, base_content)

def post_document_edit(handler, user_account, document_account_id, document_id, version, name, tags_added, tags_removed, user_ids_added, user_ids_removed, patches, used_quota):
	start_quota = quota.get_request_cpu_usage()
	
	document, document_account = get_document_and_document_account(handler, user_account, document_account_id, document_id)
	if document == None or document_account == None:
		return None, None, None
		
	dmp = diff_match_patch()
	body = document.get_body()
	edit = Edit(parent=document, account=user_account, version=document.version + 1)
	puts = [document, edit, document_account]
	conflicts = []
	content = None

	document_user_id = document_account.user.user_id()
	if document_user_id in user_ids_removed:
		user_ids_removed.remove(document_user_id)
	
	if (patches != None):
		dmp.Match_Threshold = 0.75
		patches = dmp.patch_fromText(patches)
		results = dmp.patch_apply(patches, body.content)
		content = results[0]
		index = 0
		for result in results[1]:
			if result == False:
				conflicts.append(dmp.patch_toText([patches[index]]))
			index += 1
	
	if len(conflicts) > 0:
		edit.conflicts = ''.join(conflicts)
		edit.conflicts_resolved = False
	
	if (content != None and content != body.content):
		patches = dmp.patch_make(body.content, content)
		patches = dmp.patch_toText(patches)
		edit.patches = patches
		body.content = content
		body.content_size = len(content)
		puts.append(body)

	if (name != None and name != document.name):
		if version >= document.name_version:
			edit.old_name = document.name
			edit.new_name = name
			document.name = name
			document.name_version = edit.version;
		else:
			name = document.name
	
	if len(tags_added) > 0:
		edit.tags_added = tags_added
		document.tags = list_union(document.tags, tags_added)

	if len(tags_removed) > 0:
		edit.tags_removed = tags_removed
		document.tags = list_minus(document.tags, tags_removed)

	if len(user_ids_added) > 0:
		edit.user_ids_added = user_ids_added
		document.user_ids = list_union(document.user_ids, user_ids_added)

	if len(user_ids_removed) > 0:
		edit.user_ids_removed = user_ids_removed
		document.user_ids = list_minus(document.user_ids, user_ids_removed)
	
	if edit.version % document.edits_cache_modulo == 0:
		edit.cached_document_name = document.name
		edit.cached_document_tags = document.tags
		edit.cached_document_user_ids = document.user_ids
		edit.cached_document_content = body.content

	end_quota = quota.get_request_cpu_usage()
		
	document.version = edit.version
	document.edits_size += edit.size()
	document_account.documents_size += edit.size()
	document_account.documents_cpu += ((end_quota - start_quota) + used_quota)
	
	db.put(puts)
	
	return document_account, document, body, edit, name

class BaseHandler(webapp.RequestHandler):
	def head(self, *args):
		self.get(*args)
		self.response.clear()

	def handle_exception(self, exception, debug_mode):
		webapp.RequestHandler.handle_exception(self, exception, debug_mode)

def render(file, template_values={}):
	path = os.path.join(os.path.dirname(__file__) + '/templates', file)
	if (os.path.exists(path)):
		return template.render(path, template_values)
	else:
		return False

class AdminHandler(BaseHandler):
	@require_account
	def get(self, account):
		if account.user.email() == "jesse@hogbaysoftware.com":
			self.response.out.write(render("Admin.html", { 'title' : "Admin", 'size_accounts' : Account.gql("ORDER BY documents_size DESC").fetch(100), 'cpu_accounts' : Account.gql("ORDER BY documents_cpu DESC").fetch(100) } ))		
		else:
			self.redirect(users.create_login_url("/admin"), False)

class ClientHandler(BaseHandler):
	def get(self):
		if self.request.path.find("/documents/") == 0:
			user = users.get_current_user()
			if user:
				service = service_name()
				self.response.out.write(render("Documents.%s.html" % service, { 'service_name' : service, 'user_name' : user.email(), 'logout_url' : users.create_logout_url("/") } ))		
			else:
				self.redirect(users.create_login_url("/documents/"), False)
		else:
			self.redirect("/documents/", True)
		
class DocumentsHandler(BaseHandler):
	@require_account
	def get(self, account):
		cache_key = user_id_for_user(account.user)
		cached_response = memcache.get(cache_key)

		if cached_response is None:
			document_dicts = []
			for document in account.get_documents():
				document_dicts.append(document.to_index_dictionary())			
			cached_response = simplejson.dumps(document_dicts)
			memcache.set(cache_key, cached_response)

		self.response.headers['Content-Type'] = 'application/json'
		self.response.out.write(cached_response)
	
	@require_account
	def post(self, account):
		try:
			jsonDocument = simplejson.loads(self.request.body)
			name = jsonDocument.get('name')
			name = 'Untitled' if name == None or len(name) == 0 else re.split(r"(\r\n|\r|\n)", name, 1)[0]
			tags = list_from_string(jsonDocument.get('tags'))
			user_ids = list_with_user_id(list_from_string(jsonDocument.get('user_ids')), user_id_for_user(account.user))
			content = jsonDocument.get('content', '')
			content = re.sub(r"(\r\n|\r)", "\n", content)

			def txn():
				document = Document(parent=account, version=0, edits_size=len(name) + len(content), edits_cache_modulo=10, name=name, tags=tags, user_ids=user_ids)
				document.put()
				edit = Edit(parent=document, account=account, version=0, new_name=name, tags_added=tags, user_ids_added=user_ids, cached_document_name=name, cached_document_content=content)
				body = Body(parent=document, content=content, content_size=len(content))
				account.documents_size += document.edits_size
				db.put([edit, body, account])
				return document
		
			document = db.run_in_transaction(txn)
			document.clearMemcache()
		except db.TransactionFailedError:
			self.error(503)
			return
		except runtime.DeadlineExceededError:
			self.write_deadline_exceeded_response(self.response, name, account.user.email())
			return
		
		self.response.set_status(201)
		self.response.headers.add_header("Location", document.uri())
		write_json_response(self.response, document.to_document_dictionary())

class DocumentsBatchHandler(BaseHandler):
	@require_account
	def post(self):
		pass
		# Future work. Allow client to bundle multiple requests and perform them all at once, instead of needing to
		# make a full http request/response cycle for each one.
		#
		#for request in simplejson.loads(self.request.body):
		#	method = request["method"]
		#	url = request["url"]
		#	body = request["body"]
	
class ConflictsHandler(BaseHandler):
	@require_account
	def get(self, account):
		conflict_dicts = []
		for edit in account.get_edits_with_unresolved_conflicts().fetch(10):
			if edit.is_valid():
				conflict_dicts.append(edit.to_conflict_dictionary())
		write_json_response(self.response, conflict_dicts)
		
class DocumentHandler(BaseHandler):
	@require_document
	def get(self, user_account, document_account, document):
		write_json_response(self.response, document.to_document_dictionary())
	
	def post(self, account_id, document_id):
		method = self.request.headers.get('X-HTTP-Method-Override')
		if (method == "PUT"):
			self.put(account_id, document_id)
		elif (method == "DELETE"):
			self.delete(account_id, document_id)
		else:
			self.error(405)
	
	@require_document
	def put(self, user_account, document_account, document):
		try:
			start_quota = quota.get_request_cpu_usage()
		
			jsonDocument = simplejson.loads(self.request.body)
			version = jsonDocument.get('version')
			version = None if version == None else int(version)
			name = jsonDocument.get('name')
			name = 'Untitled' if name == None or len(name) == 0 else re.split(r"(\r\n|\r|\n)", name, 1)[0]
			tags = list_from_string(jsonDocument.get('tags'))
			user_ids = list_from_string(jsonDocument.get('user_ids'))
			content = jsonDocument.get('content', None)			

			if name == None and user_ids == None and (version == None or content == None):
				self.error(400)
				return

			version_name, version_tags, version_user_ids, version_content = get_document_version(self, document, version)

			if version_name == None:
				return
		
			if content != None:
				content = re.sub(r"(\r\n|\r)", "\n", content)
				dmp = diff_match_patch()
				patches = dmp.patch_toText(dmp.patch_make(version_content, content))
			else:
				patches = None
			
			tags_added = []
			tags_removed = []
			if len(tags) > 0:
				tags_added = list_minus(tags, version_tags)
				tags_removed = list_minus(version_tags, tags)

			user_ids_added = []
			user_ids_removed = []
			if len(user_ids) > 0:
				user_ids_added = list_minus(user_ids, version_user_ids)
				user_ids_removed = list_minus(version_user_ids, user_ids)
			
			end_quota = quota.get_request_cpu_usage()
				
			document_account, document, body, edit, name = db.run_in_transaction(post_document_edit, self, user_account, document_account.key().id(), document.key().id(), version, name, tags_added, tags_removed, user_ids_added, user_ids_removed, patches, end_quota - start_quota)
			document.clearMemcache(user_ids_removed)
			document_state = document.to_document_dictionary()
			if edit.conflicts:
				document_state["conflicts"] = edit.conflicts
				
			write_json_response(self.response, document_state)
		except db.TransactionFailedError:
			self.error(503)
		except runtime.DeadlineExceededError:
			self.write_deadline_exceeded_response(self.response, document.name, user_account.user.email())
			
	@require_account
	def delete(self, user_account, document_account_id, document_id):
		version = self.request.get('version', None)
		version = None if version == None else int(version)
		
		if version == None:
			self.error(400)
			return
		
		def txn():
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
			document = db.run_in_transaction(txn)
			document.clearMemcache()
		except ValueError:
			pass
		except db.TransactionFailedError:
			self.error(503)

class DocumentEditsHandler(BaseHandler):
	@require_document_edits_paging
	def get(self, user_account, document_account, document, edits_start, edits_end, edits_next, edits_previous):
		start = self.request.get('start', 0)
		end = self.request.get('end', document.version)
		page = self.request.get('end', 1)
		write_json_response(self.response, document.get_edits_in_json_read_form(int(start), int(end)))

	@require_account
	def post(self, user_account, document_account_id, document_id):
		try:
			jsonDocument = simplejson.loads(self.request.body)
			version = jsonDocument.get('version', None)
			name = jsonDocument.get('name', None)
			name = None if name == None or len(name) == 0 else re.split(r"(\r\n|\r|\n)", name, 1)[0]
			tags_added = list_from_string(jsonDocument.get('tags_added', None))
			tags_removed = list_from_string(jsonDocument.get('tags_removed', None))
			user_ids_added = list_from_string(jsonDocument.get('user_ids_added', None))
			user_ids_removed = list_from_string(jsonDocument.get('user_ids_removed', None))
			patches = jsonDocument.get('patches', None)

			if version == None or (name == None and len(tags_added) == 0 and len(tags_removed) == 0 and len(user_ids_added) == 0 and len(user_ids_removed) == 0 and patches == None):
				self.error(400)
				return

			try:
				version = int(version)
			except:
				self.error(400)
				return
			
			document_account, document, body, edit, name = db.run_in_transaction(post_document_edit, self, user_account, document_account_id, document_id, version, name, tags_added, tags_removed, user_ids_added, user_ids_removed, patches, 0)			
			document.clearMemcache(user_ids_removed)
			document_edits = document.get_edits_in_json_read_form(version + 1, document.version)
			
			if name:
				document_edits['name'] = name;
			
			if edit.conflicts:
				document_edits["conflicts"] = edit.conflicts
			write_json_response(self.response, document_edits)
		except db.TransactionFailedError:
			self.error(503)
		except runtime.DeadlineExceededError:
			self.write_deadline_exceeded_response(self.response, document_id, user_account.user.email())

class DocumentEditHandler(BaseHandler):
	@require_document_edit
	def get(self, user_account, document_account, document, edit):
		if self.request.path.find("versions") > 0:
			name, tags, user_ids, content = get_document_version(self, document, edit.version)
			version = {}
			version["name"] = name
			version["tags"] = tags
			version["user_ids"] = user_ids
			version["content"] = content
			version["created"] = str(edit.created)
			write_json_response(self.response, version)
		else:
			write_json_response(self.response, document.get_edits_in_json_read_form(edit.version, edit.version))
			
	def post(self, account_id, document_id, edit_version):
		method = self.request.headers.get('X-HTTP-Method-Override')
		if (method == "PUT"):
			self.put(account_id, document_id, edit_version)
		else:
			self.error(405)

	@require_document_edit
	def put(self, user_account, document_account, document, edit):
		self.request.method = 'POST' # hack so that request.get() works.
		conflicts_resolved = simplejson.loads(self.request.body).get('conflicts_resolved', False)
		self.request.method = 'PUT' # undo hack.
				
		if conflicts_resolved:
			edit.conflicts_resolved = None
		else:
			edit.conflicts_resolved = False
			
		edit.put()

class DocumentsCronHandler(BaseHandler):
	def get(self):
		if True:			
			return
		
		def delete_document_txn(document):
			to_delete = []
			
			edits = db.GqlQuery("SELECT __key__ FROM Edit WHERE ANCESTOR IS :document", document=document).fetch(10)
			to_delete.extend(edits)
			if (len(edits) < 10):
				account = document.parent()
				account.documents_size -= document.edits_size
				to_delete.append(document)
				body = document.get_body()
				if body:
					to_delete.append(body)
				db.put(account)
			db.delete(to_delete)
		
		for each in Document.gql('WHERE deleted = True').fetch(10):
			db.run_in_transaction(delete_document_txn, each)
			
		query = Body.gql('ORDER BY __key__')

		# Use a query parameter to keep track of the last key of the last
		# batch, to know where to start the next batch.
		last_key_str = self.request.get('last')
		if last_key_str:
		  last_key = db.Key(last_key_str)
		  query = Body.gql('WHERE __key__ > :1 ORDER BY __key__', last_key)

		# For batches of 20, fetch 21, then use result #20 as the "last"
		# if there is a 21st.
		fetch_count = 100
		bodys = query.fetch(fetch_count + 1)
		new_last_key_str = None
		if len(bodys) == (fetch_count + 1):
			new_last_key_str = str(bodys[fetch_count - 1].key())

		puts = []
		for body in bodys:
			if not body.content_size:
				body.content_size = len(body.content)
				puts.append(body)
			#if document.content:
			#	if not document.content.empty():
			#		self.response.out.write(str(document.key()))
					
				#body = document.get_body()
				#if not body:
				#	body = Body(parent=document, content=document.content, content_size=len(document.content))
				#	document.content = None
				#	puts.append(document)
				#	puts.append(body)
				#	self.response.out.write(str(document.key()))
				#else:
				#	document.content = None
				#	puts.append(document)					
					#self.response.out.write(str(document.key()))
			
		db.put(puts)
		
		self.response.out.write("\n\n")
		self.response.out.write(new_last_key_str)
		
		#for account in Account.all().fetch(1000):
		#	user = account.user
		#	account.user_id = user.user_id()
		#	account.put()
		#to_delete = []
		#for document in Document.all().fetch(1000):
		#	if document.deleted:
		#		pass
		#	document.name_version = 0
		#	document.put()
		#to_delete = []
		#for deleted in Deleted.all().fetch(10):
		#	edits = Edit.gql('WHERE ANCESTOR IS :document', document=deleted.document_key).fetch(10)
		#	to_delete.extend(edits)
		#	if (len(edits) < 10):
		#		to_delete.append(deleted)
		#db.delete(to_delete)

def main():
	application = webapp.WSGIApplication([
		('/admin/?', AdminHandler),
		('/documents', ClientHandler),
		('/documents/', ClientHandler),
		('/v1/documents/?', DocumentsHandler),
		('/v1/documents/conflicts/?', ConflictsHandler),
		('/v1/documents/([0-9]+)-([0-9]+)/?', DocumentHandler),
		('/v1/documents/([0-9]+)-([0-9]+)/edits/?', DocumentEditsHandler),
		('/v1/documents/([0-9]+)-([0-9]+)/edits/([0-9]+)/?', DocumentEditHandler),
		('/v1/documents/([0-9]+)-([0-9]+)/versions/([0-9]+)/?', DocumentEditHandler),
		('/v1/cron', DocumentsCronHandler),
		], debug=True)
		
	wsgiref.handlers.CGIHandler().run(application)

if __name__ == '__main__':
	main()
