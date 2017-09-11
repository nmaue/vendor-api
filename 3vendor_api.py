"""
Usage
------

.. argparse::
	:filename: 3vendor_api.py
	:func: _return_parser
	:prog: python 3vendor_api.py


Details
--------

The following is an example of the minimum:

.. code-block:: console
	
	python 3vendor_api.py

Functions
----------
"""

from suds.client import Client
from suds import WebFault
import logging
import argparse
import xml.etree.ElementTree as ET
import json
import ConfigParser
import ast
from suds.transport.https import HttpAuthenticated
from urllib2 import HTTPSHandler
import ssl
import rt
import os

# We need to pass a self-signed cert
# https://stackoverflow.com/questions/37327368/bypass-ssl-when-im-using-suds-for-consume-web-service
def create_suds_client(args, url):
	"""Create context used for suds based on args passed

	Args:
		args: Argument namespace created by argparse
		url: A string of the soap api url

	Returns:
		suds.client.Client object for soap api
	"""
	class CustomTransport(HttpAuthenticated):
		def u2handlers(self):
			handlers = HttpAuthenticated.u2handlers(self)
			if args.cafile is not "ignore":
				ctx = ssl.create_default_context(cafile = args.cafile)
			else:
				# Create an unverified HTTPS connection
				ctx = ssl._create_unverified_context()
		
			handlers.append(HTTPSHandler(context=ctx))
			return handlers

	# retxml=True means that it will not parse the response as XML- just as plaintext
	try:
		mainClient = Client(url, transport=CustomTransport(), retxml=True)
	except:
		mainClient = Client(url, retxml=True)

	return mainClient

def getRelevantXML(xmlstr):
	"""Converts xml string to dictionary of tickets from vendor, selecting the relevant info

	Args:
		xmlstr: A string version of the XML returned from the soap api

	Returns:
		A dictionary of dictionaries of the tickets. 
		
		The key of the outer dict is the ticket number, with all the relevant fields in the inner dict
		
		Ex:
		{
			'1234': {
				ticketId: '1234',
				'ticketType': 'INCIDENT'
				... more fields
			},
			'5678': {
				ticketId: '5678',
				'ticketType': 'INCIDENT'
				... more fields
			},
		}
	"""
	tree = ET.fromstring(xmlstr)
	ansDict = dict()
	for element in tree.iter():
		if "getUpdatesResponse" in element.tag:
			root = element
			for ticket in root.findall('ticket'):
				# Populate a dictionary of tickets.
				relevantFields = ['ticketId', 'ticketType', 'ticketVersion', 'symptomDescription', 'detailedDescription', 'status', 'severity', 'externalTicketNum']
				relevantFieldsDict = dict()
				for ticketElement in ticket:
					if ticketElement.tag in relevantFields:
						relevantFieldsDict[ticketElement.tag] = ticketElement.text
					relevantFieldsDict['worklogs'] = dict()
					if ticketElement.tag == 'worklogs':
						relevantFieldsDict['worklogs'].update({ticketElement.findText("dateCreated"): ticketElement.findText("description")})
				ansDict[ticket.find('ticketId').text] = relevantFieldsDict
			# Break out of 'for element in tree.iter()' loop
			break
	# Return answer as Dict
	return ansDict

def create_rt_client(args):
	"""Creates the RT rest api client

	Args:
		args: An argument namespace created by argparser

	Returns
		An rt.Rt object, already logged in
	"""
	config = ConfigParser.ConfigParser()
	config.read(os.path.join(args.config_path, "tssrtir.conf"))
	tracker = rt.Rt(config.get("RTResourceConf", "RESTurl"))
	if args.no_ssl: tracker.session.verify = False
	tracker.login(config.get("RTResourceConf", "username"), config.get("RTResourceConf", "password"))
	return tracker

def delNotHigh(ticketDict):
	"""Create new dictionary of only High ticket

	Args:
		ticketDict: A dictionary of tickets like returned in 'getRelevantXML'

	Returns:
		A ticket dictionart of the same type returned in 'getRelevantXML'
	"""
	ansDict = dict()
	for ticketId, ticket in ticketDict.iteritems():
		if ticket['severity'].lower() == "High".lower():
			ansDict[ticketId] = ticket
	return ansDict

def get_v_config(args):
	"""Create dictionary of vendor api configuration

	Args:
		args: A namespace of arguments from the argparser

	Returns:
		A dictionary with the vendor api configuration
	"""
	config = ConfigParser.ConfigParser()
	config.read(os.path.join(args.config_path, "vendorapi.conf"))
	output = {
		"username": config.get("VendorAPI", "username"),
		"password": config.get("VendorAPI", "password"),
		"url": config.get("VendorAPI", "SOAPurl")
	}
	return output

def _return_parser():
	"""A hidden method that created the argument parser. Required for autodoc"""
	# Adding arguments for argparse
	parser = argparse.ArgumentParser(description='Vendor API')

	# Verbosity flags
	parser.add_argument('-v', "--verbose", help="Add verbosity", dest='verbose', required=False, action='store_true')
	
	# Cert requirement
	parser.add_argument("--cafile", help="Server certificate of the server", dest='cafile', required=False)
	parser.add_argument('-k', help="Create an unverified HTTPS connection", dest='no_ssl', required=False, action='store_true')

	# Config Directory
	parser.add_argument("--config-directory", help="Directory where configs are, no slash please", dest='config_path', required=False, default=os.getcwd())

	return parser

def prepare():
	"""Gathers the arguments and sets up the environment

	Returns:
		A namespace with all the arguments
	"""
	parser = _return_parser()
	args = parser.parse_args()

	if args.verbose:
		logging.basicConfig(level=logging.INFO)
		logging.getLogger('suds.client').setLevel(logging.DEBUG)
		logging.getLogger('suds.transport').setLevel(logging.DEBUG)
		logging.getLogger('suds.xsd.schema').setLevel(logging.DEBUG)
		logging.getLogger('suds.wsdl').setLevel(logging.DEBUG)
		#TODO Rewrite the RT module with logging

	if args.no_ssl:
		args.cafile = "ignore"

	return args

def commit(args):
	"""The main method that runs the script

	Args:
		args: A namespace of arguments returned from argparser
	"""
	vconfig = get_v_config(args)
	mainClient = create_suds_client(args, vconfig["url"])
	tracker = create_rt_client(args)
	try:
		res = mainClient.service.getUpdates(vconfig["username"], vconfig["password"], ticketType = 'INCIDENT', limit  = 50, assignedToCustomer = 'false')
	except WebFault:
		# Vendor is returning errors so we are just going to die if we can't get it.
		# I will be increasing the Cron time to compensate for it not running
		print("Vendor returned an error, exiting...")
		exit(1)
	splitres = res.splitlines()
	# # Ignore HTTP response headers
	soapres = '\n'.join(splitres[5:-1])
	ans = getRelevantXML(soapres)
	ans = ast.literal_eval(json.dumps(delNotHigh(ans))) # This helps deal with the syntax errors when creating ticket
	for ticketId in ans:
		try:
			ticket = Ticket(tracker, mainClient, vconfig["username"], vconfig["password"], **ans[ticketId])
		except:
			continue
		
		try:
			ticket.commit()
		except:
			continue
	tracker.logout()

def main():
	"""Prepares then runs script"""
	args = prepare()
	commit(args)

# Only run from command line, not import
if __name__ == "__main__":
	main()


################
# End of Scrip
# Starting Class
################

class Ticket(object):
	"""The object that is created by a vendor ticket.
	Attributes:
		tracker: An rt.Rt object passed on creation, must have already authenticated
		wsdl: A suds.client.Client object passed on creation, 
		rtticket: A string of the RT Ticket number
		vticket: A string of the V ticket number
		vversion: A string of the V version number
		vcreds: A dictionary of the V username and password
		content: A string of the body of the ticket
		subject: A string of the V subject
		worklogs: A dictionary of the time:worklog content
	"""
	def __init__(self, tracker, wsdl, username, password, **kwargs):
		"""Creates object and assigns attributes. Removes unicode chars from content

		Args:
			tracker: An rt.Rt object passed on creation, must have already authenticated
			wsdl: A suds.client.Client object passed on creation
			username: A string of the vendor username
			password: A string of the vendor password
			**kwargs: Keyword arguments from the vendor ticket

		Raises:
			Exception: Fails to acknowledge the update from Vendor
		"""
		self.tracker = tracker
		self.wsdl = wsdl
		self.vcreds = {"username": username, "password": password}
		if 'externalTicketNum' in kwargs.keys():
			self.rtticket = kwargs['externalTicketNum']
		else:
			self.rtticket = None
		self.vticket = str(kwargs['ticketId'])
		self.vversion = str(kwargs['ticketVersion'])
		self.content = str("".join([i if ord(i) < 128 else ' ' for i in kwargs['detailedDescription']])) # Remove unicode errors when creating RT ticket
		self.subject = str(kwargs['symptomDescription'])
		self.worklogs = kwargs['worklogs']
		prepare = self.acknowledge_update()
		if not prepare:
			raise Exception("Failed to acknowledge " + self.vticket)

	def create_rt(self):
		"""Creates RT ticket and sets rtticket attribute"""
		args = {
			"Subject": "[Vendor Ticket - {0}] {1}".format(self.vticket, self.subject),
			"Text": str(self.content),
			"CF_19": "Vendor", # Source
			"CF_68": str(self.vticket), # V Ticket
			"CF_69": str(self.vversion), # V Version
			"CF_13": "High" # Criticality
		}
		self.rtticket = self.tracker.create_ticket(Queue='Incident Reports', **args)

	def update_rt(self):
		"""Gets RT history and updates the RT ticket with new V worklogs"""
		history = self.tracker.get_history(self.rtticket)
		for date, content in self.worklogs:
			found = False
			for item in history:
				if item["Creator"].lower() == "Vendor".lower() and item["Type"].lower() == "Comment".lower():
					rtdate = item["Content"].split("--")[0].trim()
					if rtdate == date.trim():
						found = True
						break
			if not found:
				text = date.trim() + "\n--\n" + content
				self.tracker.comment(self.rtticket, text=text)

	def acknowledge_update(self):
		"""Acknowledge the update from vendor (required to make changes)"""
		res = self.wsdl.service.acknowledgeUpdate(self.vcreds["username"], self.vcreds["password"], self.vversion)
		# Check if response code == SUCCESS or FAILURE
		# Ignore HTTP response headers
		splitres = res.splitlines()
		soapres = '\n'.join(splitres[5:-1])
		responseCode = self.findWithinXML(soapres, 'code')
		return responseCode == "SUCCESS"
		

	def send_rt_num_v(self):
		"""Adds the RT number to Vendor external ticket number field"""
		res = self.wsdl.service.updateTicket(self.vcreds["username"], self.vcreds["password"], self.vticket, {'externalTicketNum':str(self.rtticket)})
		# Check if response code == SUCCESS or FAILURE
		# Ignore HTTP response headers
		splitres = res.splitlines()
		soapres = '\n'.join(splitres[5:-1])
		responseCode = self.findWithinXML(soapres, 'code')
		return responseCode == "SUCCESS"

	@staticmethod
	def findWithinXML(xmlStr, tag):
		"""Static method to find something in the XML

		Args:
			xmlStr: A string of the XML to search through
			tag: A string of the tag to look for
		"""
		tree = ET.fromstring(xmlStr)	
		for element in tree.iter():
			if element.tag == tag:
				return (element.text)

	def commit(self):
		"""Decides what needs to happen and does it

		Raises:
			Exception: Failed to update the V ticket adding RT number
		"""
		if self.rtticket is None:
			self.create_rt()
			resp = self.send_rt_num_v()
			if not resp:
				raise Exception ("Failed to update " + self.vticket + " with RT number " + self.rtticket)

		else:
			self.update_rt()


