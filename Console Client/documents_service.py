#!/usr/bin/env python

import os
import sys
import simplejson
import documents_service_support

class DocumentsService():
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
		return self.server.Send("/v1/documents", body=simplejson.dumps({ "name" : name, "content" : content }))
		
		return simplejson.loads(self.server.Send("/v1/documents"))

	""" Get server document.

		Args:
			id: Document's id
		Returns:
			Document dictionary with the keys: id, version, name, content
	"""
	def GET_document(self, id, version=None):
		if version:
			return simplejson.loads(self.server.Send("/v1/documents/%s/versions/%s" % (id, version)))
		else:
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
	def PUT_document(self, id, version, name=None, content=None):
		body = {}
		if version: body['version'] = version
		if name: body['name'] = name
		if content: body['content'] = content
		return self.server.Send("/v1/documents/%s" % id, body=simplejson.dumps(body), method="PUT")

	""" Delete document.

		Args:
			id: Document's id
			version: Documents version. Must match current version on server for delete to succeed.
	"""
	def DELETE_document(self, id, version):
		return self.server.Send("/v1/documents/%s" % id, method="DELETE", version=version)

google_id = "google_id"
google_pass = "google_pass"		
documents_service = DocumentsService("hogbaywriteroom", "www.writeroom.ws", google_id, google_pass)

for each_index_dictionary in documents_service.GET_documents():
	each_full_dictionary = documents_service.GET_document(each_index_dictionary["id"])
	print "----------------\nName: %s" % each_full_dictionary["name"]
	print "Content: %s" % each_full_dictionary["content"]
