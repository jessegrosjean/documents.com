#!/usr/bin/env python

import os
import sys
import simplejson
import documents_service_support

class DocumentsService(object):
	def __init__(self, service, service_host, user, password):
		self.server = documents_service_support.HttpRpcServer(service_host, lambda: (user, password), documents_service_support.GetUserAgent(), service, save_cookies=True)
	
	""" Get index list of server documents.

		Returns:
			Array of dictionaries. Each with the keys: id, version, name
	"""
	def GET_documents(self):
		return simplejson.loads(self.server.Send("/v1/documents"))

	""" Post new document.

		Args:
			name: New document's name
			content: New document's content
		Returns:
			New document's server state.
	"""
	def POST_document(self, name, content):
		return simplejson.loads(self.server.Send("/v1/documents", body=simplejson.dumps({ "name" : name, "content" : content })))

	""" Get server document.

		Args:
			id: Document's id
		Returns:
			Document dictionary with the keys: id, version, name, content
	"""
	def GET_document(self, id):
		return simplejson.loads(self.server.Send("/v1/documents/%s" % id))

	""" Update server document.

		Args:
			id: Document's id
			version: Local version of the document.
			name: New name for document.
			content: New content for document.
		Returns:
			Document's new state on server after applying your changes.
			May also include a 'conflicts' key if there were conflicts.
	"""
	def PUT_document(self, id, version, name=None, patches=None):
		body = {}
		if version: body['version'] = version
		if name: body['name'] = name
		if patches: body['patches'] = patches
		return self.server.Send("/v1/documents/%s" % id, body=simplejson.dumps(body), method="PUT")

	""" Delete document.

		Args:
			id: Document's id
			version: Documents version. Must match current version on server for delete to succeed.
	"""
	def DELETE_document(self, id, version):
		return self.server.Send("/v1/documents/%s" % id, method="DELETE", version=version)

	""" Get document revisions.

		Args:
			document_id: Document's id
		Returns:
			Keys for each saved revision of the document.
	"""
	def GET_document_revisions(self, document_id):
		return self.server.Send("/v1/documents/%s/revisions" % document_id)

	""" Get document revision.

		Args:
			document_id: Document's id
			revision_id: Revision's id
		Returns:
			Revisions dictionary with keys id, version, name, content
	"""
	def GET_document_revision(self, document_id, revision_id):
		return self.server.Send("/v1/documents/%s/revisions/%s" % (document_id, revision_id))
		
	""" Delete document revision.

		Args:
			document_id: Document's id
			revision_id: Revision's id
	"""
	def DELETE_document_revision(self, document_id, revision_id):
		return self.server.Send("/v1/documents/%s/revisions/%s" % (document_id, revision_id), method="DELETE")