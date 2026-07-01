from burp import ITab, IBurpExtender, IHttpListener, IContextMenuFactory, IMessageEditorController, IHttpRequestResponseWithMarkers, ITextEditor
from array import array
from datetime import datetime
from threading import Lock
from json import loads, dumps
from threading import Thread
from re import search

from javax.swing import JTable, JPanel, JToggleButton, JCheckBox, JMenuItem, JTree, JSplitPane, JEditorPane, JScrollPane, JTabbedPane, SwingUtilities, JLabel, JSpinner, SpinnerNumberModel
from javax.swing.table import TableRowSorter, AbstractTableModel
from javax.swing.tree import DefaultMutableTreeNode, TreePath
from javax.swing.text.html import HTMLEditorKit
from java.net import URLEncoder
from java.awt import Color, Dimension
from java.awt.event import MouseAdapter, AdjustmentListener, ActionListener
from java.util import LinkedList, ArrayList
from java.util.concurrent import Semaphore
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
		self.max_workers = 5
		# Semaphore for limiting concurrent full-scan processes (per request)
		self.semaphore = Semaphore(self.max_workers)
		# Semaphore for limiting concurrent parameter tests inside each scan
		self.param_semaphore = Semaphore(20)  # adjust as needed

		# SQLi settings to reduce timeout false positives
		self.sql_timeout_seconds = 10
		self.sql_time_threshold = 4.0
		self.sql_max_reasonable_delay = 15.0

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

		# SQLi timeout and threshold configuration
		self.sqlTimeoutLabel = JLabel("SQLi Request Timeout (sec):")
		self.sqlTimeoutLabel.setBounds(40, 205, 180, 25)
		self.configtab.add(self.sqlTimeoutLabel)

		self.sqlTimeoutSpinner = JSpinner(SpinnerNumberModel(10, 5, 30, 1))
		self.sqlTimeoutSpinner.setBounds(220, 205, 70, 25)
		self.configtab.add(self.sqlTimeoutSpinner)

		self.sqlThresholdLabel = JLabel("Time-based Threshold (sec):")
		self.sqlThresholdLabel.setBounds(40, 235, 180, 25)
		self.configtab.add(self.sqlThresholdLabel)

		self.sqlThresholdSpinner = JSpinner(SpinnerNumberModel(4, 3, 10, 1))
		self.sqlThresholdSpinner.setBounds(220, 235, 70, 25)
		self.configtab.add(self.sqlThresholdSpinner)

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

	def _adjustDivider(self):
		self._splitpane.setDividerLocation(0.8)

	# Initialize ReTrishul Tabs
	def tabsInit(self):
		self.logTable = Table(self)
		tableWidth = self.logTable.getPreferredSize().width
		SwingUtilities.invokeLater(DividerRunnable(self))
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
					# Check if it's a YAML request to trigger scan even without standard parameters
					is_yaml = False
					headers_list = requestInfo.getHeaders()
					for h in headers_list:
						if 'Content-Type' in h and ('yaml' in h.lower() or 'yml' in h.lower()):
							is_yaml = True
							break
					if len(param_new) != 0 or is_yaml:
						if self._callbacks.isInScope(requeststr):
							# Start the scanning in a separate thread
							t = Thread(target=self.sendRequestToReTrishul, args=(messageInf,))
							t.daemon = True  # So the thread dies when Burp exits
							t.start()
		return

	def _buildUpdatedRequest(self, request, headers, param_name, param_value, param_type, new_value):
		if param_type in (0, 1):
			encoded_value = URLEncoder.encode(new_value, "UTF-8")
			new_param = self._helpers.buildParameter(param_name, encoded_value, param_type)
			return self._helpers.updateParameter(request, new_param)
		elif param_type == 6:  # JSON
			request_str = self._helpers.bytesToString(request)
			try:
				body_start = request_str.find('\r\n\r\n') + 4
				body = request_str[body_start:]
				data = loads(body)
				def update(d, key, val):
					if isinstance(d, dict):
						for k, v in d.items():
							if k == key:
								d[k] = val
								return True
							elif isinstance(v, (dict, list)):
								if update(v, key, val):
									return True
					elif isinstance(d, list):
						for item in d:
							if isinstance(item, (dict, list)):
								if update(item, key, val):
									return True
					return False
				if update(data, param_name, new_value):
					new_body = dumps(data)
					new_headers = [h for h in headers if not h.lower().startswith('content-length')]
					new_headers.append('Content-Length: ' + str(len(new_body)))
					return self._helpers.buildHttpMessage(new_headers, new_body)
				else:
					return None
			except Exception as e:
				print("[ReTrishul] JSON update error:", e)
				return None
		elif param_type == 7:  # YAML (simple line replacement)
			request_str = self._helpers.bytesToString(request)
			lines = request_str.splitlines()
			new_lines = []
			found = False
			for line in lines:
				if line.strip().startswith(param_name + ':'):
					new_lines.append(param_name + ': ' + new_value)
					found = True
				else:
					new_lines.append(line)
			if found:
				new_body = '\n'.join(new_lines)
				new_headers = [h for h in headers if not h.lower().startswith('content-length')]
				new_headers.append('Content-Length: ' + str(len(new_body)))
				return self._helpers.buildHttpMessage(new_headers, new_body)
			else:
				return None
		else:
			return None

	# Main processing of ReTrishul
	def sendRequestToReTrishul(self, messageInfo):
		self.semaphore.acquire()
		try:
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
			
			# Add YAML parameters if Content-Type indicates YAML
			headers_list = requestInfo.getHeaders()
			for h in headers_list:
				if 'Content-Type' in h and ('yaml' in h.lower() or 'yml' in h.lower()):
					yaml_params = self._extract_yaml_parameters(request)
					# Create fake parameter objects
					class FakeParam:
						def __init__(self, n, v, t):
							self._name = n
							self._value = v
							self._type = t
						def getName(self):
							return self._name
						def getValue(self):
							return self._value
						def getType(self):
							return self._type
					for name, value, typ in yaml_params:
						param_new.append(FakeParam(name, value, typ))
					break

			# Parallel parameter testing using threads (Jython compatible) with semaphore
			results = []
			threads = []
			param_results = [None] * len(param_new)

			def test_param(index, param):
				name = param.getName()
				ptype = param.getType()
				param_value = param.getValue()
				result = self._test_single_param(request, headers, name, param_value, ptype, Comp_req, xss_enabled, sqli_enabled, ssti_enabled, time_taken)
				param_results[index] = (param, result)

			# Wrapper to acquire/release param_semaphore
			def test_param_with_semaphore(index, param):
				self.param_semaphore.acquire()
				try:
					test_param(index, param)
				finally:
					self.param_semaphore.release()

			for i, param in enumerate(param_new):
				t = Thread(target=test_param_with_semaphore, args=(i, param))
				t.daemon = True
				threads.append(t)
				t.start()

			# Wait for all threads
			for t in threads:
				t.join()

			results = [r for r in param_results if r is not None]

			# Process results from parallel tests
			for param, result in results:
				xss_status, xss_score, xss_attack, xss_desc, sqli_status, sqli_score, sqli_attack, sqli_desc, ssti_status, ssti_score, ssti_attack, ssti_desc = result
				
				resultxss.append(xss_status)
				resultsqli.append(sqli_status)
				resultssti.append(ssti_status)
				
				if xss_attack:
					xssreqresp.append(xss_attack)
					xss_description.append(xss_desc)
					xssflag = self.checkBetterScore(xss_score, xssflag)
				
				if sqli_attack:
					sqlireqresp.append(sqli_attack)
					sqli_description.append(sqli_desc)
					sqliflag = self.checkBetterScore(sqli_score, sqliflag)
				
				if ssti_attack:
					sstireqresp.append(ssti_attack)
					ssti_description.append(ssti_desc)
					sstiflag = self.checkBetterScore(ssti_score, sstiflag)

			if self.xsscheck.isSelected():
				html_xss_found = False
				for i, status in enumerate(resultxss):
					if (status == self.FOUND or status == self.CHECK) and xssreqresp[i] is not None:
						resp = xssreqresp[i].getResponse()
						if resp:
							content = self._helpers.analyzeResponse(resp)
							mime = content.getStatedMimeType().lower()
							if "html" in mime or "text/html" in str(content.getHeaders()):
								html_xss_found = True
								break
				
				if html_xss_found and xssflag >= 2:
					final_XSS = self.FOUND
				elif xssflag >= 1:
					final_XSS = self.CHECK   # CHECK for both HTML tentative and non-HTML reflection
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
		finally:
			self.semaphore.release()
	
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
		"""
		Advanced XSS detection with context-aware payload generation.
		Phase 1: Probe with neutral marker for context detection.
		Phase 2: Detect reflection context using neutral marker position.
		Phase 3: Generate and test targeted payloads based on reflected chars and context.
		"""
		# ---------- Phase 1: Probe for raw character reflection ----------
		# Use a neutral marker (no special chars) to locate reflection position for context.
		probe_start = "PROBE_START"
		probe_end = "PROBE_END"
		# Markers for special characters (each contains a unique substring and the actual char)
		# Format: "KEY_char" where char is the actual special character.
		marker_defs = [
			("LT", "<"), ("GT", ">"), ("QUOT", "\""), ("SING", "'"),
			("SLASH", "/"), ("BSLASH", "\\"), ("BACKTICK", "`"),
			("BRACE_O", "{"), ("BRACE_C", "}"), ("PAREN_O", "("),
			("PAREN_C", ")"), ("EQ", "="), ("ALERT", "alert"),
			("ONERROR", "onerror"), ("SCRIPT", "script")
		]
		# Build probe payload: neutral start + all markers + neutral end
		probe_payload = probe_start
		for key, char in marker_defs:
			probe_payload += "XSS_" + key + "_" + char
		probe_payload += probe_end

		updated_request = self._buildUpdatedRequest(request, headers, param_name, param_value, param_type, probe_payload)
		if updated_request is None:
			return (self.NOT_FOUND, 0, None, "")

		probe_response = self.makeRequest(original_message, updated_request)
		if probe_response is None:
			return (self.NOT_FOUND, 0, None, "")

		response_bytes = probe_response.getResponse()
		if response_bytes is None:
			return (self.NOT_FOUND, 0, None, "")
		response_str = self._helpers.bytesToString(response_bytes)

		# Find neutral marker positions (use start for context detection)
		start_pos = response_str.find(probe_start)
		if start_pos == -1:
			return (self.NOT_FOUND, 0, None, "")

		# Determine which special characters are reflected raw (the marker string itself appears)
		reflected_chars = set()
		for key, char in marker_defs:
			marker = "XSS_" + key + "_" + char
			if marker in response_str:
				reflected_chars.add(char)

		# Early exit: if no critical raw chars are reflected, XSS is highly unlikely
		if not reflected_chars:
			return (self.NOT_FOUND, 0, None, "")

		# ---------- Phase 2: Detect context using the neutral marker position ----------
		context_info = self._detect_context(response_str, start_pos)

		# ---------- Phase 3: Generate and test targeted payloads ----------
		payloads = self._generate_xss_payloads(context_info, reflected_chars)

		best_score = 0
		best_status = self.NOT_FOUND
		best_attack = None
		best_desc = ""

		# Test each generated payload
		for idx, payload_template in enumerate(payloads):
			# Add a unique marker to verify raw reflection for this specific payload
			unique_marker = "XSS_MARKER_%d_" % idx
			# Construct the final payload: marker + template (with context placeholders filled)
			final_payload = payload_template.format(
				marker=unique_marker,
				tag=context_info.get('tag_name', 'div'),
				attr=context_info.get('attr_name', '')
			)

			updated_request = self._buildUpdatedRequest(
				request, headers, param_name, param_value, param_type, final_payload
			)
			if updated_request is None:
				continue

			attack = self.makeRequest(original_message, updated_request)
			if attack is None:
				continue

			attack_response = attack.getResponse()
			if attack_response is None:
				continue
			attack_response_str = self._helpers.bytesToString(attack_response)

			# Check if our unique marker is reflected raw
			if unique_marker in attack_response_str:
				# Raw reflection of the marker indicates the payload structure worked
				score_increment = 2
				desc = "Payload <b>%s</b> reflected successfully with marker <b>%s</b>." % (
					self._helpers.urlDecode(final_payload.replace(unique_marker, "")),
					unique_marker
				)
				# Bonus if this is a sensitive context
				if context_info['context'] in ['QUOTED_ATTR', 'UNQUOTED_ATTR', 'SCRIPT_BLOCK']:
					score_increment += 1
				if "alert" in final_payload and "alert" in attack_response_str:
					score_increment += 1  # Strong evidence

				best_score += score_increment
				if score_increment >= 2 and best_attack is None:
					best_attack = attack
					best_desc = desc
			else:
				# Marker not reflected raw, maybe it was encoded or filtered
				continue

		# Determine final status based on best_score
		if best_score >= 4:
			best_status = self.FOUND
		elif best_score >= 2:
			best_status = self.CHECK
		else:
			best_status = self.NOT_FOUND

		if best_attack is None:
			# If no payload worked but we had raw chars, at least return the probe response
			return (best_status, best_score, probe_response, "Raw chars reflected but no specific payload succeeded. Manual check advised.")
		
		return (best_status, best_score, best_attack, best_desc)

	def _detect_context(self, response_str, position):
		"""
		Detect the HTML context at a given position in the response string.
		Uses a simple state machine to avoid confusion with embedded markers.
		Returns a dict: {'context': str, 'tag_name': str, 'attr_name': str}
		Possible contexts: TEXT_NODE, QUOTED_ATTR, UNQUOTED_ATTR, SCRIPT_BLOCK,
						   TEXTAREA, COMMENT, STYLE
		"""
		# Get a window around the position (e.g., 300 chars each side)
		start = max(0, position - 300)
		end = min(len(response_str), position + 300)
		window = response_str[start:end]
		rel_pos = position - start

		# Initialize context
		context = "TEXT_NODE"
		tag_name = ""
		attr_name = ""

		# 1. Check if inside a comment <!-- ... -->
		comment_start = window.rfind("<!--", 0, rel_pos)
		comment_end = window.find("-->", rel_pos)
		if comment_start != -1 and comment_end != -1 and comment_start < rel_pos < comment_end:
			return {'context': 'COMMENT', 'tag_name': '', 'attr_name': ''}

		# 2. Check if inside <script> ... </script>
		script_start = window.rfind("<script", 0, rel_pos)
		script_end = window.find("</script", rel_pos)
		if script_start != -1 and script_end != -1 and script_start < rel_pos < script_end:
			return {'context': 'SCRIPT_BLOCK', 'tag_name': 'script', 'attr_name': ''}

		# 3. Check if inside <textarea> ... </textarea>
		textarea_start = window.rfind("<textarea", 0, rel_pos)
		textarea_end = window.find("</textarea", rel_pos)
		if textarea_start != -1 and textarea_end != -1 and textarea_start < rel_pos < textarea_end:
			return {'context': 'TEXTAREA', 'tag_name': 'textarea', 'attr_name': ''}

		# 4. Check if inside <style> ... </style>
		style_start = window.rfind("<style", 0, rel_pos)
		style_end = window.find("</style", rel_pos)
		if style_start != -1 and style_end != -1 and style_start < rel_pos < style_end:
			return {'context': 'STYLE', 'tag_name': 'style', 'attr_name': ''}

		# 5. Check if inside an HTML tag (between < and >)
		# Find the nearest '<' before position
		open_tag_start = window.rfind("<", 0, rel_pos)
		if open_tag_start != -1:
			# Find the '>' that closes this tag, starting from the '<' itself
			open_tag_end = window.find(">", open_tag_start + 1)
			if open_tag_end != -1 and open_tag_start < rel_pos < open_tag_end:
				# We are inside a tag
				tag_content = window[open_tag_start:open_tag_end]
				# Extract tag name
				tag_name_match = search(r"<([a-zA-Z0-9]+)", tag_content)
				if tag_name_match:
					tag_name = tag_name_match.group(1)
				
				# Check if inside quotes
				last_double_quote = tag_content.rfind('"', 0, rel_pos - open_tag_start)
				last_single_quote = tag_content.rfind("'", 0, rel_pos - open_tag_start)
				next_double_quote = tag_content.find('"', rel_pos - open_tag_start)
				next_single_quote = tag_content.find("'", rel_pos - open_tag_start)

				in_quotes = False
				quote_char = None
				if last_double_quote > last_single_quote and (next_double_quote == -1 or next_double_quote > rel_pos - open_tag_start):
					in_quotes = True
					quote_char = '"'
				elif last_single_quote > last_double_quote and (next_single_quote == -1 or next_single_quote > rel_pos - open_tag_start):
					in_quotes = True
					quote_char = "'"

				if in_quotes:
					# Extract attribute name
					attr_start = tag_content.rfind(" ", 0, rel_pos - open_tag_start)
					if attr_start == -1:
						attr_start = 0
					attr_segment = tag_content[attr_start:rel_pos - open_tag_start].strip()
					if '=' in attr_segment:
						attr_name = attr_segment.split('=')[0].strip()
					else:
						attr_name = attr_segment.split()[0] if attr_segment else ""
					return {'context': 'QUOTED_ATTR', 'tag_name': tag_name, 'attr_name': attr_name}
				else:
					# Inside tag but not in quotes (unquoted attribute)
					attr_start = tag_content.rfind(" ", 0, rel_pos - open_tag_start)
					if attr_start == -1:
						attr_start = 0
					attr_segment = tag_content[attr_start:rel_pos - open_tag_start].strip()
					if '=' in attr_segment:
						attr_name = attr_segment.split('=')[0].strip()
					else:
						attr_name = attr_segment.split()[0] if attr_segment else ""
					return {'context': 'UNQUOTED_ATTR', 'tag_name': tag_name, 'attr_name': attr_name}

		# If not inside any specific context, it's text node
		return {'context': 'TEXT_NODE', 'tag_name': tag_name, 'attr_name': attr_name}

	def _generate_xss_payloads(self, context_info, reflected_chars):
		"""
		Generate a list of payload templates filtered by available raw reflected characters.
		Each template is a string that can be formatted with {marker}, {tag}, {attr}.
		"""
		context = context_info['context']
		tag = context_info.get('tag_name', 'div')
		attr = context_info.get('attr_name', '')

		# Base payload templates with their requirements (characters that must be reflected raw)
		all_templates = []

		# --- Payloads for TEXT_NODE ---
		if context == 'TEXT_NODE':
			if '<' in reflected_chars and '>' in reflected_chars:
				all_templates.append({
					'requires': {'<', '>'},
					'template': '</{tag}><script>alert("{marker}")</script><{tag}>'
				})
				all_templates.append({
					'requires': {'<', '>'},
					'template': '<script>alert("{marker}")</script>'
				})
				all_templates.append({
					'requires': {'<', '>', '='},
					'template': '<img src=x onerror=alert("{marker}")>'
				})

		# --- Payloads for QUOTED_ATTR ---
		elif context == 'QUOTED_ATTR':
			if '"' in reflected_chars:
				all_templates.append({
					'requires': {'"'},
					'template': '" onerror=alert("{marker}") "'
				})
				all_templates.append({
					'requires': {'"'},
					'template': '" autofocus onfocus=alert("{marker}") "'
				})
				if '>' in reflected_chars and '<' in reflected_chars:
					all_templates.append({
						'requires': {'"', '>', '<'},
						'template': '" ><script>alert("{marker}")</script><{tag} "'
					})
			if "'" in reflected_chars:
				all_templates.append({
					'requires': {"'"},
					'template': "' onerror=alert('{marker}') '"
				})
				all_templates.append({
					'requires': {"'"},
					'template': "' autofocus onfocus=alert('{marker}') '"
				})

		# --- Payloads for UNQUOTED_ATTR ---
		elif context == 'UNQUOTED_ATTR':
			all_templates.append({
				'requires': set(),
				'template': ' onerror=alert("{marker}")'
			})
			all_templates.append({
				'requires': set(),
				'template': ' autofocus onfocus=alert("{marker}")'
			})
			if '>' in reflected_chars and '<' in reflected_chars:
				all_templates.append({
					'requires': {'>', '<'},
					'template': ' ><script>alert("{marker}")</script><{tag} '
				})

		# --- Payloads for SCRIPT_BLOCK ---
		elif context == 'SCRIPT_BLOCK':
			if '<' in reflected_chars and '>' in reflected_chars and '/' in reflected_chars:
				all_templates.append({
					'requires': {'<', '>', '/'},
					'template': '</script><script>alert("{marker}")</script>'
				})
			if "'" in reflected_chars:
				all_templates.append({
					'requires': {"'"},
					'template': "'; alert('{marker}'); //"
				})
			if '"' in reflected_chars:
				all_templates.append({
					'requires': {'"'},
					'template': '"; alert("{marker}"); //'
				})

		# --- Payloads for TEXTAREA ---
		elif context == 'TEXTAREA':
			if '<' in reflected_chars and '>' in reflected_chars and '/' in reflected_chars:
				all_templates.append({
					'requires': {'<', '>', '/'},
					'template': '</textarea><script>alert("{marker}")</script>'
				})

		# --- Payloads for COMMENT ---
		elif context == 'COMMENT':
			if '-' in reflected_chars and '>' in reflected_chars and '<' in reflected_chars:
				all_templates.append({
					'requires': {'-', '>', '<'},
					'template': '--><script>alert("{marker}")</script>'
				})

		# --- Payloads for STYLE (limited, just try to break out) ---
		elif context == 'STYLE':
			if '<' in reflected_chars and '>' in reflected_chars and '/' in reflected_chars:
				all_templates.append({
					'requires': {'<', '>', '/'},
					'template': '</style><script>alert("{marker}")</script>'
				})

		# Filter templates based on available reflected characters
		# A template is valid if all its required chars are in reflected_chars
		valid_templates = []
		for t in all_templates:
			if t['requires'].issubset(reflected_chars):
				valid_templates.append(t['template'])

		return valid_templates
		
	def _test_sqli(self, request, headers, param_name, param_value, param_type, original_message, baseline_time):
		"""SQLi detection with combined error and time-based payloads"""
		# Read config
		threshold = float(self.sqlThresholdSpinner.getValue())
		
		# Error-based payload (single quote to trigger errors)
		error_payload = "'"
		# Time-based payload (sleep)
		time_payload = "' AND SLEEP(5)--"
		
		best_status = self.NOT_FOUND
		best_score = 0
		best_attack = None
		best_desc = ""
		
		# 1. Test error-based payload first (faster and cheaper)
		updated_request = self._buildUpdatedRequest(request, headers, param_name, param_value, param_type, error_payload)
		if updated_request:
			attack = self.makeRequest(original_message, updated_request)
			if attack:
				response_str = self._helpers.bytesToString(attack.getResponse())
				score = 0
				found_errors = []
				for error in self.error_array:
					if error in response_str:
						found_errors.append(error)
						score += 2
				if score > 0:
					status = self.FOUND if score > 3 else self.CHECK
					best_score = score
					best_status = status
					best_attack = attack
					best_desc = "Error-based SQLi detected with payload <b>" + self._helpers.urlDecode(error_payload) + "</b>. Errors: " + ", ".join(found_errors)
		
		# 2. Test time-based payload (always test for completeness)
		updated_request = self._buildUpdatedRequest(request, headers, param_name, param_value, param_type, time_payload)
		if updated_request:
			orig = datetime.today()
			attack = self.makeRequest(original_message, updated_request)
			if attack:
				new_time = datetime.today()
				diff = (new_time - orig).total_seconds()
				response_str = self._helpers.bytesToString(attack.getResponse())
				
				score = 0
				is_timeout = diff >= self.sql_max_reasonable_delay
				if not is_timeout and diff > threshold:
					score += 3
					# Also check for errors in time-based response (in case of blind)
					for error in self.error_array:
						if error in response_str:
							score += 1
							break
				
				if score > best_score:
					best_score = score
					best_status = self.FOUND if score > 3 else (self.CHECK if score > 1 else self.NOT_FOUND)
					best_attack = attack
					if not is_timeout and diff > threshold:
						best_desc = "Time-based SQLi detected with payload <b>" + self._helpers.urlDecode(time_payload) + "</b>. Delay: " + str(round(diff, 2)) + "s (baseline: " + str(round(baseline_time, 2)) + "s)."
					elif is_timeout:
						best_desc = "High delay detected but likely caused by timeout/WAF. Not counted as vulnerability."
					else:
						best_desc = "No clear SQLi evidence found."
		
		if best_attack is None:
			return (self.NOT_FOUND, 0, None, "")
		
		return (best_status, best_score, best_attack, best_desc)

	def _test_ssti(self, request, headers, param_name, param_value, param_type, original_message):
		"""SSTI detection with separate payloads for different template engines"""
		rand_str = "ssti_rand_"
		# Different payloads for different template engines, all with math operation
		payloads = [
			"{{7*7}}",		 # Jinja2 / Twig
			"${7*7}",	     # JSP / Java / Freemarker
			"<%= 7*7 %>",    # ERB / Ruby
			"#{7*7}"         # Ruby (alternative)
		]
		
		best_status = self.NOT_FOUND
		best_score = 0
		best_attack = None
		best_desc = ""
		
		for payload in payloads:
			full_payload = rand_str + payload
			
			if param_type in (0, 1):
				updated_request = self._buildUpdatedRequest(request, headers, param_name, param_value, param_type, full_payload)
			else:
				updated_request = self._buildUpdatedRequest(request, headers, param_name, param_value, param_type, full_payload)
				if updated_request is None:
					continue
			
			attack = self.makeRequest(original_message, updated_request)
			if attack is None:
				continue
			
			attack = self.markHttpMessage(attack, rand_str)
			response_str = self._helpers.bytesToString(attack.getResponse())
			
			score = 0
			if rand_str + "49" in response_str:
				score = 3  # Strong evidence
				status = self.FOUND
				desc = "Parameter <b>%s</b> evaluated <b>7*7</b> to <b>49</b> using payload <b>%s</b>. Template injection confirmed." % (self._helpers.urlDecode(param_name), payload)
			elif "49" in response_str and rand_str in response_str:
				score = 2  # Moderate evidence
				status = self.CHECK
				desc = "Parameter <b>%s</b> seems to evaluate expressions. Payload <b>%s</b> produced <b>49</b> in response. Manual check required." % (self._helpers.urlDecode(param_name), payload)
			else:
				status = self.NOT_FOUND
				desc = ""
			
			if score > best_score:
				best_score = score
				best_status = status
				best_attack = attack
				best_desc = desc
		
		if best_attack is None:
			return (self.NOT_FOUND, 0, None, "")
		
		return (best_status, best_score, best_attack, best_desc)
	
	def _test_single_param(self, request, headers, name, param_value, ptype, original_message, xss_enabled, sqli_enabled, ssti_enabled, baseline_time):
		xss_status = self.NOT_FOUND
		sqli_status = self.NOT_FOUND
		ssti_status = self.NOT_FOUND
		xss_score = 0
		sqli_score = 0
		ssti_score = 0
		xss_attack = None
		sqli_attack = None
		ssti_attack = None
		xss_desc = ""
		sqli_desc = ""
		ssti_desc = ""

		if xss_enabled:
			xss_status, xss_score, xss_attack, xss_desc = self._test_xss(request, headers, name, param_value, ptype, original_message)
		if sqli_enabled:
			sqli_status, sqli_score, sqli_attack, sqli_desc = self._test_sqli(request, headers, name, param_value, ptype, original_message, baseline_time)
		if ssti_enabled:
			ssti_status, ssti_score, ssti_attack, ssti_desc = self._test_ssti(request, headers, name, param_value, ptype, original_message)

		return (xss_status, xss_score, xss_attack, xss_desc, sqli_status, sqli_score, sqli_attack, sqli_desc, ssti_status, ssti_score, ssti_attack, ssti_desc)

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

	def _extract_yaml_parameters(self, request):
		request_str = self._helpers.bytesToString(request)
		body_start = request_str.find('\r\n\r\n') + 4
		body = request_str[body_start:]
		params = []
		for line in body.splitlines():
			if ':' in line and not line.strip().startswith('#'):
				key, value = line.split(':', 1)
				key = key.strip()
				value = value.strip()
				if key and value:
					params.append((key, value, 7))  # type 7 for YAML
		return params

class DividerRunnable(Runnable):
    def __init__(self, extender):
        self.extender = extender

    def run(self):
        self.extender._adjustDivider()

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
		
		logEntry = self._extender._log.get(self._extender.logTable.convertRowIndexToModel(row))
		parameter = logEntry._parameter
		resultxss = logEntry._resultxss
		resultsqli = logEntry._resultsqli
		resultssti = logEntry._resultssti
		
		# Add XSS issues
		for i in range(len(parameter)):
			status = resultxss[i] if i < len(resultxss) else "NO_STATUS"
			if status == self._extender.CHECK or status == self._extender.FOUND:
				self._extender.addIssues(self.xssroot, [parameter[i].getName()])
		
		# Add SQLi issues
		for i in range(len(parameter)):
			status = resultsqli[i] if i < len(resultsqli) else "NO_STATUS"
			if status == self._extender.CHECK or status == self._extender.FOUND:
				self._extender.addIssues(self.sqliroot, [parameter[i].getName()])
		
		# Add SSTI issues
		for i in range(len(parameter)):
			status = resultssti[i] if i < len(resultssti) else "NO_STATUS"
			if status == self._extender.CHECK or status == self._extender.FOUND:
				self._extender.addIssues(self.sstiroot, [parameter[i].getName()])
		
		self._extender.rowSelected = row
		self._extender.tree.expandRow(0)
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
						mime = content_resp.getStatedMimeType().lower()
						if "html" in mime or "text/html" in str(content_resp.getHeaders()):
							confidence = self.checkConfidence(logEntry._resultxss[i])
						else:
							confidence = "<b style=\"color: orange;\">Tentative (Non-HTML / API Response)</b>"

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
		# Start the scanning in a separate thread when user sends request manually
		t = Thread(target=self._extender.sendRequestToReTrishul, args=(self._messageInfo,))
		t.daemon = True
		t.start()

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
