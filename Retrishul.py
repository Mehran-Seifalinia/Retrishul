from burp import ITab, IBurpExtender, IHttpListener, IContextMenuFactory, IMessageEditorController, IHttpRequestResponseWithMarkers, ITextEditor
from array import array
from datetime import datetime
from thread import start_new_thread
from threading import Lock

from javax.swing import JTable, JPanel, JToggleButton, JCheckBox, JMenuItem, JTree, JSplitPane, JEditorPane, JScrollPane, JTabbedPane, SwingUtilities
from javax.swing.table import TableRowSorter, AbstractTableModel
from javax.swing.tree import DefaultMutableTreeNode, TreePath
from javax.swing.text.html import HTMLEditorKit
from java.net import URL, URLEncoder
from java.awt import Color, Dimension
from java.awt.event import MouseAdapter, AdjustmentListener, ActionListener
from java.util import LinkedList, ArrayList
from java.lang import Runnable, Integer, String, Math

# Initialize BurpExtender API to use Extender features
class BurpExtender(IBurpExtender, ITab, IHttpListener, IMessageEditorController, AbstractTableModel, IContextMenuFactory, IHttpRequestResponseWithMarkers, ITextEditor):
	def registerExtenderCallbacks(self, callbacks):
		self._callbacks = callbacks
		self._helpers = callbacks.getHelpers()
		callbacks.setExtensionName("ReTrishul")
		self._log = ArrayList()
		self._lock = Lock()		
		self.intercept = 0
		self.FOUND = "Found"
		self.CHECK = "Possible! Check Manually"
		self.NOT_FOUND = "Not Found"
		self.error_array = ["check the manual that corresponds to your", "You have an error", "syntax error", "SQL syntax", "SQL statement", "ERROR:", "Error:", "MySQL", "Warning:", "mysql_fetch_array()"]
		self.expected_output = ["56088","69741","83394","3885","777777777777777"]
		self._currentlyDisplayedItem = None
		
		# Initialize GUI
		self.issuesTab()
		self.advisoryReqResp()
		self.configTab()
		self.tabsInit()
		self.definecallbacks()
		print("Thank You for Installing ReTrishul")

	# Initialize Issues Tab displaying the JTree
	def issuesTab(self):
		self.root = DefaultMutableTreeNode('Issues')
		self.tree = JTree(self.root)
		self.rowSelected = -1
		self.tree.addMouseListener(mouseclick(self))
		self.issuepanel = JScrollPane()
		self.issuepanel.setPreferredSize(Dimension(300,450))
		self.issuepanel.getViewport().setView((self.tree))

	# Adding Issues to Issues TreePath
	def addIssues(self, branch, branchData=None):
		if branchData == None:
			branch.add(DefaultMutableTreeNode('No valid data'))
		else:
			for item in branchData:
				branch.add(DefaultMutableTreeNode(item))

	# Initialize the Config Tab to modify tool settings
	def configTab(self):
		self.configtab = JPanel()
		self.configtab.setLayout(None)
		self.configtab.setBounds(0, 0, 500, 400)
		
		self.startButton = JToggleButton("Intercept Off", actionPerformed=self.startOrStop)
		self.startButton.setBounds(40, 30, 200, 30)
		self.configtab.add(self.startButton)
		
		self.autoScroll = JCheckBox("Auto Scroll")
		self.autoScroll.setBounds(40, 80, 200, 30)
		self.configtab.add(self.autoScroll)
		
		self.xsscheck = JCheckBox("Detect XSS")
		self.xsscheck.setSelected(True)
		self.xsscheck.setBounds(40, 110, 200, 30)
		self.configtab.add(self.xsscheck)
		
		self.sqlicheck = JCheckBox("Detect SQLi")
		self.sqlicheck.setSelected(True)
		self.sqlicheck.setBounds(40, 140, 200, 30)
		self.configtab.add(self.sqlicheck)
		
		self.ssticheck = JCheckBox("Detect SSTI")
		self.ssticheck.setSelected(True)
		self.ssticheck.setBounds(40, 170, 200, 30)
		self.configtab.add(self.ssticheck)

	# Turn Intercept from Proxy on or off
	def startOrStop(self, event=None):
		if self.startButton.getText() == "Intercept Off":
			self.startButton.setText("Intercept On")
			self.startButton.setSelected(True)
			self.intercept = 1
		else:
			self.startButton.setText("Intercept Off")
			self.startButton.setSelected(False)
			self.intercept = 0

	# Intialize the Advisory, Request and Response Tabs
	def advisoryReqResp(self):
		self.textfield = JEditorPane("text/html", "")
		self.kit = HTMLEditorKit()
		self.textfield.setEditorKit(self.kit)
		self.doc = self.textfield.getDocument()
		self.textfield.setEditable(0)
		self.advisorypanel = JScrollPane()
		self.advisorypanel.setPreferredSize(Dimension(300,450))
		self.advisorypanel.getViewport().setView((self.textfield))
		self.selectedreq = []
		self._requestViewer = self._callbacks.createMessageEditor(self, False)
		self._responseViewer = self._callbacks.createMessageEditor(self, False)
		self._texteditor = self._callbacks.createTextEditor()
		self._texteditor.setEditable(False)

	# Initialize ReTrishul Tabs
	def tabsInit(self):
		self.logTable = Table(self)
		tableWidth = self.logTable.getPreferredSize().width
		self.logTable.getColumn("#").setPreferredWidth(Math.round(tableWidth / 50 * 0.1))
		self.logTable.getColumn("Method").setPreferredWidth(Math.round(tableWidth / 50 * 3))
		self.logTable.getColumn("URL").setPreferredWidth(Math.round(tableWidth / 50 * 40))
		self.logTable.getColumn("Parameters").setPreferredWidth(Math.round(tableWidth / 50 * 1))
		self.logTable.getColumn("XSS").setPreferredWidth(Math.round(tableWidth / 50 * 4))
		self.logTable.getColumn("SQLi").setPreferredWidth(Math.round(tableWidth / 50 * 4))
		self.logTable.getColumn("SSTI").setPreferredWidth(Math.round(tableWidth / 50 * 4))
		self.logTable.getColumn("Request Time").setPreferredWidth(Math.round(tableWidth / 50 * 4))
		self.tableSorter = TableRowSorter(self)
		self.logTable.setRowSorter(self.tableSorter)
		self._bottomsplit = JSplitPane(JSplitPane.HORIZONTAL_SPLIT)
		self._bottomsplit.setDividerLocation(0.7)
		self.issuetab = JTabbedPane()
		self.issuetab.addTab("Config",self.configtab)
		self.issuetab.addTab("Issues",self.issuepanel)
		self._bottomsplit.setLeftComponent(self.issuetab)
		self.tabs = JTabbedPane()
		self.tabs.addTab("Advisory",self.advisorypanel)
		self.tabs.addTab("Request", self._requestViewer.getComponent())
		self.tabs.addTab("Response", self._responseViewer.getComponent())
		self.tabs.addTab("Highlighted Response", self._texteditor.getComponent())
		self._bottomsplit.setRightComponent(self.tabs)
		self._splitpane = JSplitPane(JSplitPane.VERTICAL_SPLIT)
		self._splitpane.setDividerLocation(0.6)
		self._splitpane.setResizeWeight(1)
		self.scrollPane = JScrollPane(self.logTable)
		self._splitpane.setLeftComponent(self.scrollPane)
		self.scrollPane.getVerticalScrollBar().addAdjustmentListener(autoScrollListener(self))
		self._splitpane.setRightComponent(self._bottomsplit)

	# Initialize burp callbacks
	def definecallbacks(self):
		self._callbacks.registerHttpListener(self)
		self._callbacks.customizeUiComponent(self._splitpane)
		self._callbacks.customizeUiComponent(self.logTable)
		self._callbacks.customizeUiComponent(self.scrollPane)
		self._callbacks.customizeUiComponent(self._bottomsplit)
		self._callbacks.registerContextMenuFactory(self)
		self._callbacks.addSuiteTab(self)

	# Menu Item to send Request to ReTrishul 
	def createMenuItems(self, invocation):
		responses = invocation.getSelectedMessages()
		if len(responses) > 0:
			ret = LinkedList()
			requestMenuItem = JMenuItem("Send request to ReTrishul")

			for response in responses:
				requestMenuItem.addActionListener(handleMenuItems(self, response, "request"))
			ret.add(requestMenuItem)
			return ret
		return None

	# Highlighting Response
	def markHttpMessage( self, requestResponse, responseMarkString ):
		responseMarkers = None
		if responseMarkString:
			response = requestResponse.getResponse()
			if response is None:
				return
			responseMarkBytes = self._helpers.stringToBytes( responseMarkString )
			start = self._helpers.indexOf( response, responseMarkBytes, False, 0, len( response ) )
			if -1 < start:
				responseMarkers = [ array( 'i',[ start, start + len( responseMarkBytes ) ] ) ]

		requestHighlights = [array( 'i',[ 0, 5 ] )]
		return self._callbacks.applyMarkers( requestResponse, requestHighlights, responseMarkers )
		
	def getTabCaption(self):
		return "ReTrishul"

	def getUiComponent(self):
		return self._splitpane

	# Table Model to display URL's and results based on the log size
	def getRowCount(self):
		try:
			return self._log.size()
		except:
			return 0

	def getColumnCount(self):
		return 8

	def getColumnName(self, columnIndex):
		data = ['#','Method', 'URL', 'Parameters', 'XSS', 'SQLi', "SSTI", "Request Time"]
		try:
			return data[columnIndex]
		except IndexError:
			return String

	def getColumnClass(self, columnIndex):
		data = [Integer, String, String, Integer, String, String, String, String]
		try:
			return data[columnIndex]
		except IndexError:
			return String

	# Get Data stored in log and display in the respective columns
	def getValueAt(self, rowIndex, columnIndex):
		logEntry = self._log.get(rowIndex)
		if columnIndex == 0:
			return rowIndex+1
		if columnIndex == 1:
			return logEntry._method
		if columnIndex == 2:
			return logEntry._url.toString()
		if columnIndex == 3:
			return len(logEntry._parameter)
		if columnIndex == 4:
			return logEntry._XSSStatus
		if columnIndex == 5:
			return logEntry._SQLiStatus
		if columnIndex == 6:
			return logEntry._SSTIStatus
		if columnIndex == 7:
			return logEntry._req_time
		return String

	def getHttpService(self):
		return self._currentlyDisplayedItem.getHttpService()

	def getRequest(self):
		return self._currentlyDisplayedItem.getRequest()

	def getResponse(self):
		return self._currentlyDisplayedItem.getResponse()
		
	# For Intercepted requests perform tests in scope
	def processHttpMessage(self, toolFlag, messageIsRequest, messageInf):
		if self.intercept == 1:
			if toolFlag == self._callbacks.TOOL_PROXY:
				if not messageIsRequest:
					requestInfo = self._helpers.analyzeRequest(messageInf)
					requeststr = requestInfo.getUrl()
					parameters = requestInfo.getParameters()
					param_new = [p for p in parameters if p.getType() != 2]
					if len(param_new) != 0:
						if self._callbacks.isInScope(requeststr):
							start_new_thread(self.sendRequestToReTrishul, (messageInf,))
		return

	def _buildUpdatedRequest(self, request, headers, param_name, param_value, param_type, new_value):
		"""
		Builds a new HTTP request with the specified parameter updated to new_value.
		Handles GET, POST, and JSON parameters (type 0,1,6).
		Returns bytearray request or None if failed.
		"""
		if param_type in (0, 1):  # GET or POST
			new_param = self._helpers.buildParameter(param_name, new_value, param_type)
			return self._helpers.updateParameter(request, new_param)
		elif param_type == 6:  # JSON
			request_str = self._helpers.bytesToString(request)
			import re
			json_match = re.search(r"\s([{\[].*?[}\]])$", request_str)
			if json_match is None:
				return None
			jsonreq = json_match.group(1)
			try:
				after_name = jsonreq.split(param_name + '":', 1)[1]
			except IndexError:
				return None
			if after_name.startswith('"'):
				new_jsonreq = jsonreq.replace(param_name + '":"' + param_value, param_name + '":"' + new_value)
			else:
				new_jsonreq = jsonreq.replace(param_name + '":' + param_value, param_name + '":"' + new_value + '"')
			return self._helpers.buildHttpMessage(headers, new_jsonreq)
		return None

	# Main processing of ReTrishul
	def sendRequestToReTrishul(self,messageInfo):
		request = messageInfo.getRequest()
		req_time = datetime.today()
		requestURL = self._helpers.analyzeRequest(messageInfo).getUrl()
		port = self._get_port(requestURL)
		messageInfo = self._callbacks.makeHttpRequest(self._helpers.buildHttpService(str(requestURL.getHost()), port, requestURL.getProtocol() == "https"), request)
		if messageInfo is None:
			return
		resp_time = datetime.today()
		time_taken = (resp_time - req_time).total_seconds()
		xss_enabled = self.xsscheck.isSelected()
		sqli_enabled = self.sqlicheck.isSelected()
		ssti_enabled = self.ssticheck.isSelected()
		response = messageInfo.getResponse()

		# Initialozations of default value
		final_SQLi = self.NOT_FOUND
		final_SSTI = self.NOT_FOUND
		final_XSS = self.NOT_FOUND
		Comp_req = messageInfo
		requestInfo = self._helpers.analyzeRequest(messageInfo)
		self.content_resp = self._helpers.analyzeResponse(response)
		requestURL = requestInfo.getUrl()
		parameters = requestInfo.getParameters()
		headers = requestInfo.getHeaders()

		# Used to obtain GET, POST and JSON parameters from burp API
		param_new = [p for p in parameters if p.getType() == 0 or p.getType() == 1 or p.getType() == 6]
		xssflag=0
		sqliflag=0
		sstiflag=0
		resultxss = []
		resultsqli = []
		resultssti = []
		xssreqresp = []
		sqlireqresp = []
		sstireqresp = []
		ssti_description = []
		sqli_description = []
		xss_description = []
		
		# NEW: refactored loop using helper methods
		for param in param_new:
			name = param.getName()
			ptype = param.getType()
			param_value = param.getValue()
			xss_status = self.NOT_FOUND
			sqli_status = self.NOT_FOUND
			ssti_status = self.NOT_FOUND
			xss_desc = ""
			sqli_desc = ""
			ssti_desc = ""
			xss_attack = None
			sqli_attack = None
			ssti_attack = None
			xss_score = 0
			sqli_score = 0
			ssti_score = 0

			if xss_enabled:
				xss_status, xss_score, xss_attack, xss_desc = self._test_xss(request, headers, name, param_value, ptype, Comp_req)
				resultxss.append(xss_status)
				if xss_attack:
					xssreqresp.append(xss_attack)
					xss_description.append(xss_desc)
				xssflag = self.checkBetterScore(xss_score, xssflag)
			else:
				resultxss.append("Disabled")
				xssreqresp.append(None)
				xss_description.append("")

			if sqli_enabled:
				sqli_status, sqli_score, sqli_attack, sqli_desc = self._test_sqli(request, headers, name, param_value, ptype, Comp_req, time_taken)
				resultsqli.append(sqli_status)
				if sqli_attack:
					sqlireqresp.append(sqli_attack)
					sqli_description.append(sqli_desc)
				sqliflag = self.checkBetterScore(sqli_score, sqliflag)
			else:
				resultsqli.append("Disabled")
				sqlireqresp.append(None)
				sqli_description.append("")

			if ssti_enabled:
				ssti_status, ssti_score, ssti_attack, ssti_desc = self._test_ssti(request, headers, name, param_value, ptype, Comp_req)
				resultssti.append(ssti_status)
				if ssti_attack:
					sstireqresp.append(ssti_attack)
					ssti_description.append(ssti_desc)
				sstiflag = self.checkBetterScore(ssti_score, sstiflag)
			else:
				resultssti.append("Disabled")
				sstireqresp.append(None)
				ssti_description.append("")

		if self.xsscheck.isSelected():
			if xssflag >= 2:
				final_XSS = self.FOUND
			elif xssflag >= 1:
				final_XSS = self.CHECK
			else:
				final_XSS = self.NOT_FOUND
		else:
			final_XSS = "Disabled"

		if self.sqlicheck.isSelected():
			if sqliflag > 3:
				final_SQLi = self.FOUND
			elif sqliflag > 2:
				final_SQLi = self.CHECK
			else:
				final_SQLi = self.NOT_FOUND
		else:
			final_SQLi = "Disabled"

		if self.ssticheck.isSelected():
			if sstiflag > 1:
				final_SSTI = self.FOUND
			elif sstiflag > 0:
				final_SSTI = self.CHECK
			else:
				final_SSTI = self.NOT_FOUND
		else:
			final_SSTI = "Disabled"

		self.addToLog(messageInfo, final_XSS, final_SQLi, final_SSTI, param_new, resultxss, resultsqli, resultssti, xssreqresp, sqlireqresp, sstireqresp , xss_description, sqli_description, ssti_description, req_time.strftime('%H:%M:%S %m/%d/%y'))

	# Function used to check if the score originally and mentioned is better
	def checkBetterScore(self, score, ogscore):
		if score > ogscore:
			ogscore = score
		return ogscore
		
	def _get_port(self, url):
		port = url.getPort()
		if port == -1:
			return 443 if url.getProtocol() == "https" else 80
		return port
		
	def _test_xss(self, request, headers, param_name, param_value, param_type, original_message):
		payload_array = ["<", ">", "\\\\'asd", "\\\\\"asd", "\\", "'\""]
		json_payload_array = ["<", ">", "\\\\'asd", "\\\"asd", "\\", "\'\\\""]
		rand_str = "testtest"
		payload_all = ""
		json_payload = ""
		for payload in payload_array:
			payload_all += rand_str + payload
		for payload in json_payload_array:
			json_payload += rand_str + payload
		payload_all = URLEncoder.encode(payload_all, "UTF-8")
		json_payload = URLEncoder.encode(json_payload, "UTF-8")

		if param_type in (0, 1):
			updated_request = self._buildUpdatedRequest(request, headers, param_name, param_value, param_type, payload_all)
		else:
			updated_request = self._buildUpdatedRequest(request, headers, param_name, param_value, param_type, json_payload)
			if updated_request is None:
				return (self.NOT_FOUND, 0, None, "")

		attack = self.makeRequest(original_message, updated_request)
		if attack is None:
			return (self.NOT_FOUND, 0, None, "")
		response_str = self._helpers.bytesToString(attack.getResponse())
		score = 0
		non_encoded = ""
		for check_payload in payload_array:
			if_found = rand_str + check_payload
			if if_found in response_str:
				non_encoded += "<br>" + check_payload.replace('<', '&lt;')
				score += 1
		if score >= 2:
			status = self.FOUND
		elif score >= 1:
			status = self.CHECK
		else:
			status = self.NOT_FOUND
		description = ""
		if non_encoded:
			description = "The Payload <b>" + payload_all.replace('<', '&lt;') + "</b> was passed in the request for the paramater <b>" + self._helpers.urlDecode(param_name) + "</b>. Some Tags were observed in the output unfiltered. A payload can be generated with the observed tags.<br>Symbols not encoded for parameter <b>" + param_name + "</b>: " + non_encoded
		return (status, score, attack, description)
		
	def _test_sqli(self, request, headers, param_name, param_value, param_type, original_message, baseline_time):
		value = "' and (select * from (select(sleep(5)))a)--"
		updated_request = self._buildUpdatedRequest(request, headers, param_name, param_value, param_type, value)
		if updated_request is None:
			return (self.NOT_FOUND, 0, None, "")
		orig = datetime.today()
		attack = self.makeRequest(original_message, updated_request)
		if attack is None:
			return (self.NOT_FOUND, 0, None, "")
		new_time = datetime.today()
		response_str = self._helpers.bytesToString(attack.getResponse())
		diff = (new_time - orig).total_seconds()
		score = 0
		if (diff - baseline_time) > 3:
			score = 4
		found_text = ""
		for error in self.error_array:
			if error in response_str:
				found_text += error
				score += 1
		if score > 2:
			status = self.FOUND
		elif score > 1:
			status = self.CHECK
		else:
			status = self.NOT_FOUND
		desc = ""
		if found_text != '':
			desc = "The payload <b>" + self._helpers.urlDecode(value) + "</b> was passed in the request for parameter <b>" + self._helpers.urlDecode(param_name) + "</b>. Some errors were generated in the response which confirms that there is an Error based SQLi. Please check the request and response for this parameter"
		elif (diff - baseline_time) > 3:
			desc = "The payload <b>" + self._helpers.urlDecode(value) + "</b> was passed in the request for parameter <b>" + self._helpers.urlDecode(param_name) + "</b>. The response was in a delay of <b>" + str(diff) + "</b> seconds as compared to original <b>" + str(baseline_time) + "</b> seconds. This indicates that there is a time based SQLi. Please check the request and response for this parameter"
		return (status, score, attack, desc)

	def _test_ssti(self, request, headers, param_name, param_value, param_type, original_message):
		payload_array = ["${123*456}", "<%=123*567%>", "{{123*678}}"]
		json_payload_array = ["$\{123*456\}", "<%=123*567%>", "\{\{123*678\}\}"]
		rand_str = "jjjjjjj"
		payload_all = ""
		json_payload = ""
		for payload in payload_array:
			payload_all += rand_str + payload
		for payload in json_payload_array:
			json_payload += rand_str + payload
		if param_type in (0, 1):
			updated_request = self._buildUpdatedRequest(request, headers, param_name, param_value, param_type, payload_all)
		else:
			updated_request = self._buildUpdatedRequest(request, headers, param_name, param_value, param_type, json_payload)
			if updated_request is None:
				return (self.NOT_FOUND, 0, None, "")
		attack = self.makeRequest(original_message, updated_request)
		if attack is None:
			return (self.NOT_FOUND, 0, None, "")
		attack = self.markHttpMessage(attack, rand_str)
		response_str = self._helpers.bytesToString(attack.getResponse())
		score = 0
		desc = ""
		desc_parts = []
		for output in self.expected_output:
			if_found = rand_str + output
			if if_found in response_str:
				if output == "56088":
					desc_parts.append("Parameter <b>%s</b> is using <b>Java</b> Template<br>The value <b>${123*456}</b> was passed which gave result as <b>56088</b>" % self._helpers.urlDecode(param_name))
					score = max(score, 2)
				elif output == "69741":
					desc_parts.append("Parameter <b>%s</b> is using <b>Ruby</b> Template<br>The value <b><%=123*567%></b> was passed which gave result as <b>69741</b>" % self._helpers.urlDecode(param_name))
					score = max(score, 2)
				elif output == "83394":
					payload_twig = "{{5*'777'}}"
					if param_type in (0,1):
						req2 = self._buildUpdatedRequest(request, headers, param_name, param_value, param_type, payload_twig)
					else:
						req2 = self._buildUpdatedRequest(request, headers, param_name, param_value, param_type, "{{5*'777'}}")
					if req2:
						attack2 = self.makeRequest(original_message, req2)
						if attack2:
							resp2 = self._helpers.bytesToString(attack2.getResponse())
							if "3885" in resp2:
								desc_parts.append("Parameter <b>%s</b> is using <b>Twig</b> Template<br>The value <b>{{5*'777'}}</b> was passed which gave result as <b>3885</b>" % self._helpers.urlDecode(param_name))
								score = max(score, 2)
							elif "777777777777777" in resp2:
								desc_parts.append("Parameter <b>%s</b> is using <b>Jinja2</b> Template<br>The value <b>{{5*'777'}}</b> was passed which gave result as <b>777777777777777</b>" % self._helpers.urlDecode(param_name))
								score = max(score, 2)
		desc = "<br>".join(desc_parts) if desc_parts else ""
		if score > 1:
			status = self.FOUND
		elif score > 0:
			status = self.CHECK
		else:
			status = self.NOT_FOUND
		return (status, score, attack, desc)

	def makeRequest(self, messageInfo, message):
		try:
			requestURL = self._helpers.analyzeRequest(messageInfo).getUrl()
			port = self._get_port(requestURL)
			service = self._helpers.buildHttpService(str(requestURL.getHost()), port, requestURL.getProtocol() == "https")
			return self._callbacks.makeHttpRequest(service, message)
		except Exception as e:
			print("[ReTrishul] Request error for %s: %s" % (messageInfo.getUrl(), str(e)))
			return None

	def addToLog(self, messageInfo, final_XSS, final_SQLi, final_SSTI, parameters, resultxss, resultsqli, resultssti, xssreqresp, sqlireqresp, sstireqresp, xss_description, sqli_description, ssti_description, req_time):
		requestInfo = self._helpers.analyzeRequest(messageInfo)
		method = requestInfo.getMethod()
		self._lock.acquire()
		row = self._log.size()
		self._log.add(LogEntry(self._callbacks.saveBuffersToTempFiles(messageInfo), requestInfo.getUrl(),method,final_XSS,final_SQLi,final_SSTI,req_time, parameters,resultxss, resultsqli, resultssti, xssreqresp, sqlireqresp, sstireqresp, xss_description, sqli_description, ssti_description)) # same requests not include again.
		SwingUtilities.invokeLater(UpdateTableEDT(self,"insert",row,row))
		self._lock.release()

# Extend JTable to handle cell selection
class Table(JTable):

	def __init__(self, extender):
		self._extender = extender
		self.setModel(extender)
		self.xssroot = None
		self.sqliroot = None
		self.sstiroot = None
		self.addMouseListener(mouseclick(self._extender))
		self.getColumnModel().getColumn(0).setPreferredWidth(0)
		self.setRowSelectionAllowed(True)
		return

	# Set color for cells in tables
	def prepareRenderer(self, renderer, row, col):
		comp = JTable.prepareRenderer(self, renderer, row, col)
		value = self._extender.getValueAt(self._extender.logTable.convertRowIndexToModel(row), col)

		if col == 4 or col == 5 or col == 6:
			if value == self._extender.FOUND:
				comp.setBackground(Color(179, 0, 0))
				comp.setForeground(Color.WHITE)
			elif value == self._extender.CHECK:
				comp.setBackground(Color(255, 153, 51))
				comp.setForeground(Color.BLACK)
			elif value == self._extender.NOT_FOUND:
				comp.setBackground(Color.LIGHT_GRAY)
				comp.setForeground(Color.BLACK)
			elif value == "Disabled":
				comp.setBackground(Color.LIGHT_GRAY)
				comp.setForeground(Color.BLACK)
		else:
			comp.setForeground(Color.BLACK)
			comp.setBackground(Color.LIGHT_GRAY)

		selectedRow = self._extender.logTable.getSelectedRow()
		if selectedRow == row:
			comp.setBackground(Color.WHITE)
			comp.setForeground(Color.BLACK)
		return comp


	# Open Issue tab to display vulnerable parameters
	def changeSelection(self, row, col, toggle, extend):
		
		if col >= 0:
			self.performAction(row)
			self._extender.issuetab.setSelectedIndex(1)
			self._extender.tree.expandRow(0)

		if col == 4:
			if self.sqliroot is not None:
				self._extender.tree.collapsePath(TreePath(self.sqliroot.getPath()))
			if self.sstiroot is not None:
				self._extender.tree.collapsePath(TreePath(self.sstiroot.getPath()))
			if self.xssroot is not None:
				self._extender.tree.expandPath(TreePath(self.xssroot.getPath()))
		
		if col == 5:
			if self.xssroot is not None:
				self._extender.tree.collapsePath(TreePath(self.xssroot.getPath()))
			if self.sstiroot is not None:
				self._extender.tree.collapsePath(TreePath(self.sstiroot.getPath()))
			if self.sqliroot is not None:
				self._extender.tree.expandPath(TreePath(self.sqliroot.getPath()))

		if col == 6:
			if self.xssroot is not None:
				self._extender.tree.collapsePath(TreePath(self.xssroot.getPath()))
			if self.sqliroot is not None:
				self._extender.tree.collapsePath(TreePath(self.sqliroot.getPath()))
			if self.sstiroot is not None:
				self._extender.tree.expandPath(TreePath(self.sstiroot.getPath()))

		JTable.changeSelection(self, row, col, toggle, extend)
		return

	# Add parameters to array for every issue found for a particular request
	def performAction(self, row):
		model = self._extender.tree.getModel()
		root = model.getRoot()
		root.removeAllChildren()
		model.reload()
		self.xssroot = DefaultMutableTreeNode('Cross-Site-Scripting')
		root.add(self.xssroot)
		self.sqliroot = DefaultMutableTreeNode('SQL Injection')
		root.add(self.sqliroot)
		self.sstiroot = DefaultMutableTreeNode('Server Side Template Injection')
		root.add(self.sstiroot)
		resultxss = []
		resultsqli = []
		resultssti = []
		logEntry = self._extender._log.get(self._extender.logTable.convertRowIndexToModel(row))
		resultxss = logEntry._resultxss
		resultsqli = logEntry._resultsqli
		resultssti = logEntry._resultssti
		parameter = logEntry._parameter
		
		for i in range(len(parameter)):
			if resultxss[i] == self._extender.CHECK or resultxss[i] == self._extender.FOUND:
				array = []
				array.append(parameter[i].getName())
				self._extender.addIssues(self.xssroot, array)
			if resultsqli[i] == self._extender.CHECK or resultsqli[i] == self._extender.FOUND:
				array = []
				array.append(parameter[i].getName())
				self._extender.addIssues(self.sqliroot, array)
			if resultssti[i] == self._extender.CHECK or resultssti[i] == self._extender.FOUND:
				array = []
				array.append(parameter[i].getName())
				self._extender.addIssues(self.sstiroot, array)
		self._extender.rowSelected = row
		return

# Log to Store Data of Requests
class LogEntry:

	def __init__(self, requestResponse, url, method, final_XSS, final_SQLi, final_SSTI, req_time, parameter, resultxss, resultsqli, resultssti, xssreqresp, sqlireqresp, sstireqresp, xss_description, sqli_description, ssti_description):
		self._requestResponse = requestResponse
		self._url = url
		self._method = method
		self._XSSStatus = final_XSS
		self._SQLiStatus = final_SQLi
		self._SSTIStatus = final_SSTI
		self._req_time = req_time
		self._parameter = parameter
		self._resultxss = resultxss
		self._resultsqli = resultsqli
		self._resultssti = resultssti
		self._xssreqresp = xssreqresp
		self._sqlireqresp = sqlireqresp
		self._sstireqresp = sstireqresp
		self._ssti_description = ssti_description
		self._xss_description = xss_description
		self._sqli_description = sqli_description
		return

# Mouse Adapter to click on Table and Tree to display data
class mouseclick(MouseAdapter):

	def __init__(self, extender):
		self._extender = extender

	def mouseReleased(self, event):
		self.path = self._extender.tree.getLastSelectedPathComponent()
		if self.path != None and self._extender.rowSelected >= 0:
			row = self._extender.rowSelected
			logEntry = self._extender._log.get(self._extender.logTable.convertRowIndexToModel(row))
			parameter = logEntry._parameter
			xssreqresp = logEntry._xssreqresp
			sqlireqresp = logEntry._sqlireqresp
			sstireqresp = logEntry._sstireqresp
			xss_description = logEntry._xss_description
			sqli_description = logEntry._sqli_description
			ssti_description = logEntry._ssti_description
			url = logEntry._url.toString()
			for i in range(len(parameter)):
				if str(self.path.getParent()) == "Server Side Template Injection":
					if str(self.path) == parameter[i].getName():
						self._extender.textfield.setText("")
						response = sstireqresp[i].getResponse()
						confidence = self.checkConfidence(logEntry._resultssti[i])
						self._extender.kit.insertHTML(self._extender.doc, self._extender.doc.getLength(), "<h1>"+str(self.path.getParent())+"</h1>", 0, 0, None)
						self._extender.kit.insertHTML(self._extender.doc, self._extender.doc.getLength(), "<br><table cellspacing=\"1\" cellpadding=\"0\"><tr><td>Issue:</td> <td><b>"+str(self.path.getParent())+"</b></td></tr><tr><td>Severity:</td> <td><b>High</b></td></tr><td>Confidence:</td> <td>"+confidence+"</b></td><tr><td>URL:</td> <td><b>"+url+"</b></td></tr>" , 0, 0, None)
						self._extender.kit.insertHTML(self._extender.doc, self._extender.doc.getLength(), "<br><h3>Description</h3>", 0, 0, None)
						self._extender.kit.insertHTML(self._extender.doc, self._extender.doc.getLength(), "Parameter <b>" + self._extender._helpers.urlDecode(str(self.path)) + "</b> is vulnerable to SSTI.", 0, 0, None)
						self._extender.kit.insertHTML(self._extender.doc, self._extender.doc.getLength(), "<br>" + ssti_description[i], 0, 0, None)
						self._extender.kit.insertHTML(self._extender.doc, self._extender.doc.getLength(), "<br><h3>Quick Fix</h3>", 0, 0, None)
						self._extender.kit.insertHTML(self._extender.doc, self._extender.doc.getLength(), "Sandbox the template engine, sanitize user input, or avoid user-controlled template expressions.", 0, 0, None)
						self._extender.textfield.setCaretPosition(0)
						self._extender.selectedreq = sstireqresp[i]
						self._extender._requestViewer.setMessage(sstireqresp[i].getRequest(), True)
						self._extender._responseViewer.setMessage(sstireqresp[i].getResponse(), False)
						self._extender._currentlyDisplayedItem = sstireqresp[i]
						self._extender._texteditor.setText(sstireqresp[i].getResponse())
						response_str = self._extender._helpers.bytesToString(response)
						for ssti_out in self._extender.expected_output:
							if ssti_out in response_str:
								self._extender._texteditor.setSearchExpression(ssti_out)
								break
										
				elif str(self.path.getParent()) == "Cross-Site-Scripting":
					if str(self.path) == parameter[i].getName():
						self._extender.textfield.setText("")
						response = xssreqresp[i].getResponse()
						content_resp = self._extender._helpers.analyzeResponse(response)
						if content_resp.getStatedMimeType() == "HTML":
							confidence = self.checkConfidence(logEntry._resultxss[i])
						else:
							confidence = "<b style=\"color: orange;\">Tentative (Non HTML Output)</b>"
						self._extender.kit.insertHTML(self._extender.doc, self._extender.doc.getLength(), "<h1>"+str(self.path.getParent())+"</h1>", 0, 0, None)
						self._extender.kit.insertHTML(self._extender.doc, self._extender.doc.getLength(), "<br><table cellspacing=\"1\" cellpadding=\"0\"><tr><td>Issue:</td> <td><b>" + str(self.path.getParent()) + "</b></td></tr><tr><td>Severity:</td> <td><b>High</b></td></tr><tr><td>Confidence:</td> <td>" + confidence + "</b></td></tr><tr><td>URL:</td> <td><b>" + url + "</b></td></tr>" , 0, 0, None)
						self._extender.kit.insertHTML(self._extender.doc, self._extender.doc.getLength(), "<br><h3>Description</h3>", 0, 0, None)
						self._extender.kit.insertHTML(self._extender.doc, self._extender.doc.getLength(), "Parameter <b>" + self._extender._helpers.urlDecode(str(self.path)) + "</b> is vulnerable to Reflected XSS.", 0, 0, None)
						self._extender.kit.insertHTML(self._extender.doc, self._extender.doc.getLength(), "<br>" + xss_description[i], 0, 0, None)
						self._extender.kit.insertHTML(self._extender.doc, self._extender.doc.getLength(), "<br><h3>Quick Fix</h3>", 0, 0, None)
						self._extender.kit.insertHTML(self._extender.doc, self._extender.doc.getLength(), "Encode output: replace <code>&lt; &gt; &quot; &#39; &amp;</code> with HTML entities. Use context-aware encoding.", 0, 0, None)
						self._extender.textfield.setCaretPosition(0)
						self._extender.selectedreq = xssreqresp[i]
						xssreqresp[i] = self._extender.markHttpMessage(xssreqresp[i], "testtest")
						self._extender._requestViewer.setMessage(xssreqresp[i].getRequest(), True)
						self._extender._responseViewer.setMessage(xssreqresp[i].getResponse(), False)
						self._extender._currentlyDisplayedItem = xssreqresp[i]
						self._extender._texteditor.setText(xssreqresp[i].getResponse())
						self._extender._texteditor.setSearchExpression("testtest")
				elif str(self.path.getParent()) == "SQL Injection":
					if str(self.path) == parameter[i].getName():
						self._extender.textfield.setText("")
						confidence = self.checkConfidence(logEntry._resultsqli[i])
						self._extender.kit.insertHTML(self._extender.doc, self._extender.doc.getLength(), "<h1>"+str(self.path.getParent())+"</h1>", 0, 0, None)
						self._extender.kit.insertHTML(self._extender.doc, self._extender.doc.getLength(), "<br><table cellspacing=\"1\" cellpadding=\"0\"><tr><td>Issue:</td> <td><b>" + str(self.path.getParent()) + "</b></td></tr><tr><td>Severity:</td> <td><b>High</b></td></tr><tr><td>Confidence:</td> <td>" + confidence + "</b></td><tr><td>URL:</td> <td><b>" + url + "</b></td></tr>" , 0, 0, None)
						self._extender.kit.insertHTML(self._extender.doc, self._extender.doc.getLength(), "<br><h3>Description</h3>", 0, 0, None)
						self._extender.kit.insertHTML(self._extender.doc, self._extender.doc.getLength(), "Parameter <b>" + self._extender._helpers.urlDecode(str(self.path)) + "</b> is vulnerable to SQL Injection.", 0, 0, None)
						self._extender.kit.insertHTML(self._extender.doc, self._extender.doc.getLength(), "<br>" + sqli_description[i], 0, 0, None)
						self._extender.kit.insertHTML(self._extender.doc, self._extender.doc.getLength(), "<br><h3>Quick Fix</h3>", 0, 0, None)
						self._extender.kit.insertHTML(self._extender.doc, self._extender.doc.getLength(), "Use parameterized queries (prepared statements). Never concatenate user input into SQL.", 0, 0, None)
						self._extender.textfield.setCaretPosition(0)
						self._extender.selectedreq = sqlireqresp[i]
						response = sqlireqresp[i].getResponse()
						self._extender._requestViewer.setMessage(sqlireqresp[i].getRequest(), True)
						self._extender._responseViewer.setMessage(sqlireqresp[i].getResponse(), False)
						self._extender._currentlyDisplayedItem = sqlireqresp[i]
						self._extender._texteditor.setText(response)
						response_str = self._extender._helpers.bytesToString(response)
						for error in self._extender.error_array:
							if error in response_str:
								self._extender._texteditor.setSearchExpression(error)
								break
							else:
								pass

	# Color of Confidence in Description
	def checkConfidence(self, value):
		if value == self._extender.FOUND:
			return "<b style=\"color:red;\">Firm</b>"
		elif value == self._extender.CHECK:
			return "<b style=\"color:orange;\">Tentative</b>"
		else:
			return "<b style=\"color:gray;\">Unknown</b>"

# Autoscroll enabling feature
class autoScrollListener(AdjustmentListener):
	def __init__(self, extender):
		self._extender = extender

	def adjustmentValueChanged(self, e):
		if self._extender.autoScroll.isSelected() is True:
			e.getAdjustable().setValue(e.getAdjustable().getMaximum())

# Menu Iten Added on Right Click which sends request to ReTrishul
class handleMenuItems(ActionListener):

	def __init__(self, extender, messageInfo, menuName):
		self._extender = extender
		self._menuName = menuName
		self._messageInfo = messageInfo

	def actionPerformed(self, e):
		start_new_thread(self._extender.sendRequestToReTrishul, (self._messageInfo,))

# Function to insert request details into the table
class UpdateTableEDT(Runnable):

	def __init__(self,extender,action,firstRow,lastRow):
		self._extender=extender
		self._action=action
		self._firstRow=firstRow
		self._lastRow=lastRow

	def run(self):
		if self._action == "insert":
			self._extender.fireTableRowsInserted(self._firstRow, self._lastRow)
		elif self._action == "update":
			self._extender.fireTableRowsUpdated(self._firstRow, self._lastRow)
		elif self._action == "delete":
			self._extender.fireTableRowsDeleted(self._firstRow, self._lastRow)
		else:
			print("Invalid action in UpdateTableEDT")
