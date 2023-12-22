package burp;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadPoolExecutor;
import javax.swing.JMenuItem;

public class ContextMenuController implements IContextMenuFactory {
	
	private final HashMap<String,ArrayList<String>> patternMap;
	private final ArrayList<String> headerList;
	private final ThreadPoolExecutor threadPool = (ThreadPoolExecutor) Executors.newFixedThreadPool(1);
	
	public ContextMenuController(HashMap<String,ArrayList<String>> patternMap, ArrayList<String> headerList) {
		this.patternMap = patternMap;
		this.headerList = headerList;
	}

	@Override
	public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
		if(invocation.getSelectedMessages() != null && invocation.getSelectedMessages().length == 1) {
			IHttpRequestResponse message = invocation.getSelectedMessages()[0];
			if(message.getRequest() != null) {
				JMenuItem menuItem = new JMenuItem("Scan");
				menuItem.addActionListener(e -> {
					new Thread(new Runnable() {
						
						@Override
						public void run() {
							if(is4xx(message.getHttpService(), message.getRequest())) {
								IRequestInfo requestInfo = BurpExtender.callbacks.getHelpers().analyzeRequest(message.getRequest());
								byte[] requestBody = Arrays.copyOfRange(message.getRequest(), requestInfo.getBodyOffset(),
										message.getRequest().length);
								doPathModifications(requestInfo, message.getHttpService(), requestBody);
								doHeaderModifications(requestInfo, message.getHttpService(), requestBody);
							}
							else {
								BurpExtender.callbacks.printOutput("Nothing to bypass (no 4xx Response).");
							}
						}
					}).start();
				});
				
				ArrayList<JMenuItem> menuList = new ArrayList<>();
				menuList.add(menuItem);
				return menuList;
			}	
		}	
		return null;
	}
	
	private void doPathModifications(IRequestInfo requestInfo, IHttpService httpService, byte[] requestBody) {
		List<String> headerList = new ArrayList<>(requestInfo.getHeaders());
		if(headerList.size() > 0) {
			String[] firstHeaderSplit = headerList.get(0).split(" ");
			if(firstHeaderSplit.length == 3) {
				String method = firstHeaderSplit[0];
				String path = firstHeaderSplit[1];
				String protocol = firstHeaderSplit[2];
				
				HashSet<String> modifiedPaths = PathModifier.applyAllRules(path, patternMap);
				for(String modifiedPath : modifiedPaths) {
					String modifiedFirstHeader = method + " " + modifiedPath + " " + protocol;
					headerList.set(0, modifiedFirstHeader);
					byte[] modifiedMessage = BurpExtender.callbacks.getHelpers().buildHttpMessage(headerList, requestBody);
					BurpExtender.callbacks.printOutput(("Request (Path): " + modifiedFirstHeader));
					repeatRequest(httpService, modifiedMessage, "Bypass through Path: " + modifiedPath);
				}
			}
		}	
	}
	
	private void doHeaderModifications(IRequestInfo requestInfo, IHttpService httpService, byte[] requestBody) {
		for(String header : headerList) {
			List<String> headerList = new ArrayList<>(requestInfo.getHeaders());
			headerList.add(header);
			byte[] modifiedMessage = BurpExtender.callbacks.getHelpers().buildHttpMessage(headerList, requestBody);
			BurpExtender.callbacks.printOutput(("Request (Header): " + header));
			repeatRequest(httpService, modifiedMessage, "Bypass through Header: " + header);
		}
	}

	private void repeatRequest(IHttpService httpService, byte[] request, String message) {
		IHttpRequestResponse requestResponse = BurpExtender.callbacks.makeHttpRequest(httpService, request);
		checkAndCreateIssue(requestResponse, message);
		try {
			Thread.sleep(Settings.getDealayBetweenRequests());
		} catch (InterruptedException e) {
			e.printStackTrace();
		}
	}
	
	private boolean is4xx(IHttpService httpService, byte[] request) {
		IHttpRequestResponse requestResponse = BurpExtender.callbacks.makeHttpRequest(httpService, request);
		if(requestResponse.getResponse() != null) {
			IResponseInfo responseInfo = BurpExtender.callbacks.getHelpers().analyzeResponse(requestResponse.getResponse());
			short firstDigit = Short.parseShort(Short.toString(responseInfo.getStatusCode()).substring(0, 1));
			if(firstDigit == 4) {
				return true;
			}
		}
		return false;
	}
	
	private void checkAndCreateIssue(IHttpRequestResponse requestResponse, String message) {
		if(requestResponse.getResponse() != null) {
			IResponseInfo responseInfo = BurpExtender.callbacks.getHelpers().analyzeResponse(requestResponse.getResponse());
			boolean codeInForbiddenList = false;
			String codeAsString = Short.toString(responseInfo.getStatusCode());
			//Check if valid response code - could be 0
			if(codeAsString.length() == 3) {
				short firstDigit = Short.parseShort((codeAsString).substring(0, 1));
				for(short code : Settings.getForbiddenStatusCodes()) {
					
					if(firstDigit == code) {
						codeInForbiddenList = true;
						break;
					}
				}
				if(!codeInForbiddenList) {
					IScanIssue issue = new BypasserIssue(requestResponse, message);
					BurpExtender.callbacks.addScanIssue(issue);
				}
			}
			else {
				BurpExtender.callbacks.printOutput("Status Code not valid: " + responseInfo.getStatusCode());
			}
		}
	}
	
}
