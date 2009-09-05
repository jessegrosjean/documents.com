#!/usr/bin/env python

import os
import sys
import optparse
import simplejson
import documents_service

parser = optparse.OptionParser(usage="usage: %prog [options]")
parser.add_option("-u", "--user", action="store", dest="user", help="Google ID for Google Authentication.")
parser.add_option("-p", "--password", action="store", dest="password", help="Password for Google Authentication.")
parser.add_option("-c", "--service", action="store", dest="service", default="simpletextws", help="Service name for Google authentication.")
parser.add_option("-s", "--server", action="store", dest="server", default="www.simpletext.ws", help="Documents service server URL.")
options = parser.parse_args()[0]

service_instance = documents_service.DocumentsService(options.service, options.server, options.user, options.password)

class SyncedDocument(object):
	def __init__(self, path):
		self.serverVersion = -1
		self.name = s.path.split(path)[1]
		self.user_deleted = False
		
		
		self.content = data.get('content')
		self.shadowID = data.get('id')
		self.shadowVersion = data.get('version')
		self.shadowContent = data.get('content')
	
	def __init__(self, data):
		self.serverVersion = -1
		self.name = data.get('name')
		self.content = data.get('content')
		self.shadowID = data.get('id')
		self.shadowVersion = data.get('version')
		self.shadowContent = data.get('content')
	
	def local_edits(self):
		if self.shadowID != None and self.shadowVersion != None:
			edits = {}
			edits['version'] = self.shadowVersion
			if self.content != self.shadowContent:
				edits['patches'] = patches
			return edits
		return None
		
	def has_server_edits(self):
		return self.shadowVersion != self.serverVersion
		
	def isServerDocument(self):
		return self.shadowID != None
	
	def isDeletedFromServer(self):
		pass

	def isInsertedFromServer(self):
		return self.serverVersion != -1 and self.shadowVersion == None

class SyncedDocumentController(object):
	def sync_document(self, document):
		pass

	def sync_documents(self):
		syncing_documents = []

		# 1. Get server documents index, mapped by id
		server_documents_state_by_id = self.read_server_documents_state()

		# 2. Map local documents to server documents
		for each_document in self.read_local_documents():
			if each_document.isSyncedToServer():
				each_server_document_state = server_documents_state_by_id[each_document.shadowID]
				if each_server_document_state:
					each_document.serverVersion = each_server_document_state.get('version')
					del server_documents_state_by_id[each_document.shadowID]
					each_document.isDeletedFromServer = False
				else:
					each_document.isDeletedFromServer = True
				syncing_documents.append(each_document)

		for each in service_instance.GET_documents():
			servers[each['id']] = SyncedDocument(each)

	def read_server_documents_state(self):
		documents_state_by_id = {}
		for each in service_instance.GET_documents():
			documents_state_by_id[each['id']] = each
		return documents_state_by_id

	def read_local_documents(self):
		locals = {}
		locals_path = os.getcwd()

		for each in os.listdir(locals_path):
			if each.endswith('.py'):
				each_path = "%s/%s" % (locals_path, each)
				if not os.path.isdir(each_path):
					data = {}
					data['name'] = each
					data['content'] = open(each_path).read()

		shadows_path = locals_path + ".shadows"
		for each in os.listdir(locals_path):
			
		
		for each in 	
		return locals

	def read_shadows(self):
		shadows = {}
		shadows_path = os.getcwd() + ".shadows"
		if not os.path.isdir(shadows_path):
			os.mkdir(shadows_path)

		for each in os.listdir(locals_path):
			if each.endswith('.shadow'):
				shadow_id, shadow_version =  os.path.splitext[0].partition('_')
				shadow_data = {}
				shadow_data['shadowID'] = shadow_id
				shadow_data['shadowVersion'] = shadow_version
				shadow_data['shadowContent'] = open("%s/%s" % (shadows_path, each)).read()
				shadows[shadow_id] = SyncedDocument(shadow_data)
			
		return shadows
		
synced_document_controller = SyncedDocumentController()
synced_document_controller.sync_documents()