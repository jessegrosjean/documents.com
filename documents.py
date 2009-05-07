import os
import re
import logging
import datetime
import operator
import wsgiref.handlers

from django.utils import simplejson
from diff_match_patch import diff_match_patch

from google.appengine.ext import db
from google.appengine.api import users
from google.appengine.ext import webapp
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

class Account(db.Model):
	user = db.UserProperty(required=True)
	documents_size = db.IntegerProperty(required=True)

	@classmethod
	def get_account_for_user(cls, user):
		if user:
			account = Account.gql("WHERE user = :1", user).get()
			if account == None:
				account = Account(user=user, documents_size=0)
				account.put()
			else:
				account.user = user
				account.put()
			return account
		return None

	def __eq__(self, other):
		return self.user == other.user if isinstance(other, Account) else False
		
	def get_documents(self):
		return Document.gql("WHERE ANCESTOR IS :1 AND deleted = :2 ORDER BY name", self, False)
		#documents = Document.gql("WHERE ANCESTOR IS :1", self).fetch(1000)
		#documents.extend(Document.gql("WHERE user_emails = :1", self.user.email()).fetch(1000))
		#documents.sort(key=operator.attrgetter('name'))
		#return documents

	def get_edits_with_unresolved_conflicts(self):
		return Edit.gql("WHERE account = :1 AND conflicts_resolved = :2 ORDER BY created DESC", self, False)

class Document(db.Model):
	version = db.IntegerProperty(required=True)
	name = db.StringProperty(required=True)
	name_version = db.IntegerProperty(default=0)
	edits_size = db.IntegerProperty(required=True)
	edits_cache_modulo = db.IntegerProperty(required=True)
	created = db.DateTimeProperty(required=True, auto_now_add=True)
	modified = db.DateTimeProperty(required=True, auto_now=True)
	tags = db.StringListProperty()
	user_emails = db.StringListProperty()
	content = db.TextProperty()
	deleted = db.BooleanProperty(default=False)
	
	def id_string(self):
		return "%s-%s" % (self.parent_key().id(), self.key().id())
		
	def tags_string(self):
		if len(self.tags) > 0:
			return ' '.join(self.tags)
		else:
			return ""

	def user_emails_string(self):
		if len(self.user_emails) > 0:
			return ' '.join(self.user_emails)
		else:
			return ""
	
	def owner_email(self):
		return self.parent().user.email()
		
	def uri(self):
		return "/documents/%s" % self.id_string()

	def get_edits(self, start, end, sequence="ASC"):
		return Edit.gql('WHERE ANCESTOR IS :document AND version >= :start AND version <= :end ORDER BY version %s' % sequence, document=self, start=start, end=end).fetch((end - start) + 1)

	def get_account_emails(self):
		emails = []
		emails.append(self.owner_email)
		emails.extend(self.user_emails)
		return emails
		
	def get_edits_in_json_read_form(self, start, end):
		edits = {}

		name = None
		tags_added = []
		tags_removed = []
		user_emails_added = []
		user_emails_removed = []
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

			if len(edit.user_emails_added) > 0:
				user_emails_added = list_union(user_emails_added, edit.user_emails_added)
				user_emails_removed = list_minus(user_emails_removed, edit.user_emails_added)

			if len(edit.user_emails_removed) > 0:
				user_emails_removed = list_union(user_emails_removed, edit.user_emails_removed)
				user_emails_added = list_minus(user_emails_added, edit.user_emails_removed)
								
			if edit.new_name:
				name = edit.new_name

		if name: edits["name"] = name
		if len(tags_added) > 0: edits["tags_added"] = tags_added
		if len(tags_removed) > 0: edits["tags_removed"] = tags_removed
		if len(user_emails_added) > 0: edits["user_emails_added"] = user_emails_added
		if len(user_emails_removed) > 0: edits["user_emails_removed"] = user_emails_removed
		if len(patches) > 0: edits["patches"] = ''.join(patches)
		return edits
	
	def to_index_dictionary(self):
		return { 'id': self.id_string(), 'version': self.version, 'name': self.name }

	def to_document_dictionary(self):
		return { 'owner' : self.parent().user.email(), 'id': self.id_string(), 'name': self.name, 'version': self.version, 'content': self.content, 'created': str(self.created), 'modified': str(self.modified) }
	
	def clearMemcache(self, removed_emails=[]):
		keys = []
		keys.append(self.owner_email())
		keys.extend(removed_emails)
		keys.extend(self.user_emails)
		memcache.delete_multi(keys)		

class Edit(db.Model):
	account = db.ReferenceProperty(Account, required=True)
	version = db.IntegerProperty(required=True)
	old_name = db.StringProperty()
	new_name = db.StringProperty()
	tags_added = db.StringListProperty()
	tags_removed = db.StringListProperty()
	user_emails_added = db.StringListProperty()
	user_emails_removed = db.StringListProperty()
	patches = db.TextProperty()
	conflicts = db.TextProperty()
	conflicts_resolved = db.BooleanProperty(default=None)
	created = db.DateTimeProperty(required=True, auto_now_add=True)
	cached_document_name = db.StringProperty()
	cached_document_tags = db.StringListProperty()
	cached_document_user_emails = db.StringListProperty()
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
		
	def apply(self, name, tags, user_emails, content, dmp):
		if self.new_name: name = self.new_name
		if len(self.tags_added) > 0: tags = list_union(tags, self.tags_added)
		if len(self.tags_removed) > 0: tags = list_minus(tags, self.tags_removed)
		if len(self.user_emails_added) > 0: user_emails = list_union(user_emails, self.user_emails_added)
		if len(self.user_emails_removed) > 0: user_emails = list_minus(user_emails, self.user_emails_removed)
		if self.patches: content = dmp.patch_apply(dmp.patch_fromText(self.patches.encode('ascii')), content)[0]
		return (name, tags, user_emails, content)
		
	def reverse(self, name, tags, user_emails, content, dmp):
		if self.old_name: name = self.old_name
		if len(self.tags_added) > 0: tags = list_minus(tags, self.tags_added)
		if len(self.tags_removed) > 0: tags = list_union(tags, self.tags_removed)
		if len(self.user_emails_added) > 0: user_emails = list_minus(user_emails, self.user_emails_added)
		if len(self.user_emails_removed) > 0: user_emails = list_union(user_emails, self.user_emails_removed)
		if self.patches: content = dmp.patch_apply(dmp.patch_reverse(dmp.patch_fromText(self.patches.encode('ascii'))), content)[0]
		return (name, tags, user_emails, content)

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
		edit = Edit.gql('WHERE ANCESTOR IS :document AND version = :version', document=document, version=int(edit_version)).get()

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
	elif not (document.parent() == user_account or user_account.user.email() in document.user_emails):
		handler.error(401)
		return None, None

	return document, document_account

def get_document_version(handler, document, version):
	if version == document.version:
		return (document.name, document.tags, document.user_emails, document.content)
	elif version > document.version:
		handler.error(404)
		return (None, None, None, None)

	modulo = (version % document.edits_cache_modulo)

	if modulo == 0:
		edit = Edit.gql('WHERE ANCESTOR IS :document AND version = :version', document=document, version=version).get()
		return (edit.cached_document_name, edit.cached_document_tags, edit.cached_document_user_emails, edit.cached_document_content)
	else:
		if modulo > (document.edits_cache_modulo / 2):
			base_version = (version - modulo) + document.edits_cache_modulo
			edits_query = 'WHERE ANCESTOR IS :document AND version > :version AND version <= :base_version ORDER BY version DESC'
			calculate_forward = False
		else:
			base_version = (version - modulo)
			edits_query = 'WHERE ANCESTOR IS :document AND version >= :base_version AND version <= :version ORDER BY version'
			calculate_forward = True

		base_name = None
		base_tags = None
		base_user_emails = None
		base_content = None
		dmp = diff_match_patch()
		dmp.Match_Threshold = 0.0

		for edit in Edit.gql(edits_query, document=document, version=version, base_version=base_version).fetch(document.edits_cache_modulo):
			if calculate_forward:
				if base_name == None:
					base_name = edit.cached_document_name
					base_tags = edit.cached_document_tags[:]
					base_user_emails = edit.cached_document_user_emails[:]
					base_content = edit.cached_document_content
				else:
					base_name, base_tags, base_user_emails, base_content = edit.apply(base_name, base_tags, base_user_emails, base_content, dmp)
			else:
				if base_name == None:
					if edit.version % document.edits_cache_modulo == 0:
						base_name = edit.cached_document_name
						base_tags = edit.cached_document_tags[:]
						base_user_emails = edit.cached_document_user_emails[:]
						base_content = edit.cached_document_content
					else:
						base_name = document.name
						base_tags = document.tags[:]
						base_user_emails = document.user_emails[:]
						base_content = document.content

				base_name, base_tags, base_user_emails, base_content = edit.reverse(base_name, base_tags, base_user_emails, base_content, dmp)

		return (base_name, base_tags, base_user_emails, base_content)

def post_document_edit(handler, user_account, document_account_id, document_id, version, name, tags_added, tags_removed, user_emails_added, user_emails_removed, patches):
	document, document_account = get_document_and_document_account(handler, user_account, document_account_id, document_id)
	if document == None or document_account == None:
		return None, None, None
		
	dmp = diff_match_patch()
	edit = Edit(parent=document, account=user_account, version=document.version + 1)
	conflicts = []
	content = None

	if (patches != None):
		dmp.Match_Threshold = 1.0
		patches = dmp.patch_fromText(patches)
		results = dmp.patch_apply(patches, document.content)
		content = results[0]
		index = 0
		for result in results[1]:
			if result == False:
				conflicts.append(dmp.patch_toText([patches[index]]))
			index += 1
	
	if len(conflicts) > 0:
		edit.conflicts = ''.join(conflicts)
		edit.conflicts_resolved = False
	
	if (content != None and content != document.content):
		patches = dmp.patch_make(document.content, content)
		patches = dmp.patch_toText(patches)
		edit.patches = patches
		document.content = content

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

	if len(user_emails_added) > 0:
		edit.user_emails_added = user_emails_added
		document.user_emails = list_union(document.user_emails, user_emails_added)

	if len(user_emails_removed) > 0:
		edit.user_emails_removed = user_emails_removed
		document.user_emails = list_minus(document.user_emails, user_emails_removed)
	
	if edit.version % document.edits_cache_modulo == 0:
		edit.cached_document_name = document.name
		edit.cached_document_tags = document.tags
		edit.cached_document_user_emails = document.user_emails
		edit.cached_document_content = document.content
		
	document.version = edit.version
	document.edits_size += edit.size()
	document_account.documents_size += edit.size()
	document.put()
	edit.put()
	document_account.put()
	
	return document_account, document, edit, name

class ClientHandler(webapp.RequestHandler):
	def get(self):
		if self.request.path.find("/documents/") == 0:
			user = users.get_current_user()
			if user:
				path = os.path.join(os.path.dirname(__file__) + '/templates', "Documents.html")
				self.response.out.write(template.render(path, { 'user_name' : user.email(), 'logout_url' : users.create_logout_url("/") }))
			else:
				self.redirect(users.create_login_url("/documents/"), False)
		else:
			self.redirect("/documents/", True)
		
class DocumentsHandler(webapp.RequestHandler):
	@require_account
	def get(self, account):
		#json = memcache.get(account.user.email())

		#if json is None:
		#	document_dicts = []
		#	for document in account.get_documents():
		#		document_dicts.append(document.to_index_dictionary())
		#	json = simplejson.dumps(document_dicts)
		#	memcache.set(account.user.email(), json)

		#self.response.headers['Content-Type'] = 'application/json'
		#self.response.out.write(json)

		document_dicts = []
		for document in account.get_documents():
			document_dicts.append(document.to_index_dictionary())
		write_json_response(self.response, document_dicts)
	
	@require_account
	def post(self, account):
		jsonDocument = simplejson.loads(self.request.body)
		name = jsonDocument.get('name')
		name = 'Untitled' if name == None or len(name) == 0 else name
		tags = list_from_string(jsonDocument.get('tags'))
		user_emails = list_from_string(jsonDocument.get('user_emails'))
		content = jsonDocument.get('content', '')			
		content = re.sub(r"(\r\n|\r)", "\n", content) # Normalize line endings

		def txn():
			document = Document(parent=account, version=0, edits_size=len(name) + len(content), edits_cache_modulo=10, name=name, tags=tags, user_emails=user_emails, content=content)
			document.put()
			edit = Edit(parent=document, account=account, version=0, new_name=name, tags_added=tags, user_emails_added=user_emails, cached_document_name=name, cached_document_content=content)
			edit.put()
			account.documents_size += document.edits_size
			account.put()
			return document
		
		try:
			document = db.run_in_transaction(txn)
			#document.clearMemcache()
		except db.TransactionFailedError:
			self.error(503)
			return
		
		self.response.set_status(201)
		self.response.headers.add_header("Location", document.uri())
		write_json_response(self.response, document.to_document_dictionary())

class DocumentsBatchHandler(webapp.RequestHandler):
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
	
class ConflictsHandler(webapp.RequestHandler):
	@require_account
	def get(self, account):
		conflict_dicts = []
		for edit in account.get_edits_with_unresolved_conflicts().fetch(10):
			if edit.is_valid():
				conflict_dicts.append(edit.to_conflict_dictionary())
		write_json_response(self.response, conflict_dicts)
		
class DocumentHandler(webapp.RequestHandler):
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
		jsonDocument = simplejson.loads(self.request.body)
		version = jsonDocument.get('version')
		version = None if version == None else int(version)
		name = jsonDocument.get('name')
		name = 'Untitled' if name == None or len(name) == 0 else name
		tags = list_from_string(jsonDocument.get('tags'))
		user_emails = list_from_string(jsonDocument.get('user_emails'))
		content = jsonDocument.get('content', None)			

		if name == None and user_emails == None and (version == None or content == None):
			self.error(400)
			return

		version_name, version_tags, version_user_emails, version_content = get_document_version(self, document, version)

		if version_name == None:
			return
		
		if content != None:
			content = re.sub(r"(\r\n|\r)", "\n", content) # Normalize line endings
			dmp = diff_match_patch()
			patches = dmp.patch_toText(dmp.patch_make(version_content, content))
		else:
			patches = None
			
		tags_added = []
		tags_removed = []
		if len(tags) > 0:
			tags_added = list_minus(tags, version_tags)
			tags_removed = list_minus(version_tags, tags)

		user_emails_added = []
		user_emails_removed = []
		if len(user_emails) > 0:
			user_emails_added = list_minus(user_emails, version_user_emails)
			user_emails_removed = list_minus(version_user_emails, user_emails)
					
		try:
			document_account, document, edit, name = db.run_in_transaction(post_document_edit, self, user_account, document_account.key().id(), document.key().id(), version, name, tags_added, tags_removed, user_emails_added, user_emails_removed, patches)
			#document.clearMemcache(user_emails_removed)
			document_edits = document.get_edits_in_json_read_form(version, document.version)
			document_edits['content'] = document.content
			
			if name:
				document_edits['name'] = name;
			
			if edit.conflicts:
				document_edits["conflicts"] = edit.conflicts
				
			write_json_response(self.response, document_edits)
		except db.TransactionFailedError:
			self.error(503)
						
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
			document.put()
			#document_account.documents_size -= document.edits_size
			#document_account.put()
			return document

		try:
			document = db.run_in_transaction(txn)
			#document.clearMemcache()
		except ValueError:
			pass
		except db.TransactionFailedError:
			self.error(503)

class DocumentEditsHandler(webapp.RequestHandler):
	@require_document_edits_paging
	def get(self, user_account, document_account, document, edits_start, edits_end, edits_next, edits_previous):
		start = self.request.get('start', 0)
		end = self.request.get('end', document.version)
		page = self.request.get('end', 1)
		write_json_response(self.response, document.get_edits_in_json_read_form(int(start), int(end)))

	@require_account
	def post(self, user_account, document_account_id, document_id):
		jsonDocument = simplejson.loads(self.request.body)
		version = jsonDocument.get('version', None)
		name = jsonDocument.get('name', None)
		tags_added = list_from_string(jsonDocument.get('tags_added', None))
		tags_removed = list_from_string(jsonDocument.get('tags_removed', None))
		user_emails_added = list_from_string(jsonDocument.get('user_emails_added', None))
		user_emails_removed = list_from_string(jsonDocument.get('user_emails_removed', None))
		patches = jsonDocument.get('patches', None)

		if version == None or (name == None and len(tags_added) == 0 and len(tags_removed) == 0 and len(user_emails_added) == 0 and len(user_emails_removed) == 0 and patches == None):
			self.error(400)
			return

		try:
			version = int(version)
		except:
			self.error(400)
			return
			
		try:
			document_account, document, edit, name = db.run_in_transaction(post_document_edit, self, user_account, document_account_id, document_id, version, name, tags_added, tags_removed, user_emails_added, user_emails_removed, patches)			
			#document.clearMemcache(user_emails_removed)
			document_edits = document.get_edits_in_json_read_form(version + 1, document.version)
			
			if name:
				document_edits['name'] = name;
			
			if edit.conflicts:
				document_edits["conflicts"] = edit.conflicts
			write_json_response(self.response, document_edits)
		except db.TransactionFailedError:
			self.error(503)

class DocumentEditHandler(webapp.RequestHandler):
	@require_document_edit
	def get(self, user_account, document_account, document, edit):
		if self.request.path.find("versions") > 0:
			name, tags, user_emails, content = get_document_version(self, document, edit.version)
			version = {}
			version["name"] = name
			version["tags"] = tags
			version["user_emails"] = user_emails
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
		
class DocumentsCronHandler(webapp.RequestHandler):
	def get(self):
		pass
		#to_delete = []
		#for deleted in Deleted.all().fetch(10):
		#	edits = Edit.gql('WHERE ANCESTOR IS :document', document=deleted.document_key).fetch(10)
		#	to_delete.extend(edits)
		#	if (len(edits) < 10):
		#		to_delete.append(deleted)
		#db.delete(to_delete)

def main():
	application = webapp.WSGIApplication([
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
