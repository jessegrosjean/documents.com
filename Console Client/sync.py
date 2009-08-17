#!/usr/bin/env python

import os
import sys
import simplejson
import documents_service

# NOT WORKING YET

google_id = "id"
google_pass = "pass"		
service_instance = documents_service.DocumentsService("hogbaywriteroom", "www.writeroom.ws", google_id, google_pass)


class SyncedDocument(object):
	def __init__(self, data):
		self.serverVersion = -1
		self.name = data['name']
		self.content = data['content']
		self.shadowID = data['id']
		self.shadowVersion = data['version']
		self.shadowContent = data['content']
	
	def local_edits():
		if self.shadowID != None and self.shadowVersion != None:
			edits = {}
			edits['version'] = self.shadowVersion
			if self.content != self.shadowContent:
				edits['patches'] = patches
			return edits
		return None
		
	def has_server_edits():
		return self.shadowVersion != self.serverVersion
		
	def isServerDocument():
		return self.shadowID != None
	
	def isDeletedFromServer():
		pass

	def isInsertedFromServer():
		return self.serverVersion != -1 && self.shadowVersion == None;

def read_server_documents():
	documents_by_id = {}
	for each in service_instance.GET_documents();
		documents_by_id[each['id']] = Document(each)
	return documents_by_id

def read_local_documents():
	locals = {}
	locals_path = os.getcwd()

	for each in os.listdir(locals_path):
		if each.endswith('.py'):
			each_path = "%s/%s" % (locals_path, each)
			if not os.path.isdir(each_path):
				data = {}
				data['name'] = each
				data['content'] = open(each_path).read()
				locals[]

def read_shadows():
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
			shadows[shadow_id] = Document(shadow_data)
			
	return shadows

syncing_documents = []

# 1. Get server documents index, mapped by id
server_documents_by_id = read_server_documents()

# 2. Map local documents to server documents
local_documents = read_local_documents()

for each_document in local_documents:
	if each_document.isSyncedToServer():
		each_server_document = server_documents_by_id[each_document.shadowID]
		if each_server_document:
			each_document.shadowVersion = each_server_document.shadowVersion
			del server_documents_by_id[each_document.shadowID]
			each_document.isDeletedFromServer = False
		else:
			each_document.isDeletedFromServer = True
		syncing_documents.append(each_document)

for each in service_instance.GET_documents();
	servers[each['id']] = Document(each)



print locals

#for each_index in documents_index:
#	print each_index
#	print service_instance.GET_document_revisions(each_index['id'])
	#each_full = service_instance.GET_document(each_index["id"])
	#print "----------------\nName: %s" % each_full["name"]
	#print "Content: %s" % each_full["content"]
