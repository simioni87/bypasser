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
					IRequestInfo requestInfo = BurpExtender.callbacks.getHelpers().analyzeRequest(message.getRequest());
					byte[] requestBody = Arrays.copyOfRange(message.getRequest(), requestInfo.getBodyOffset(),
							message.getRequest().length);
					doHeaderModifications(requestInfo, message.getHttpService(), requestBody);
					doPathModifications(requestInfo, message.getHttpService(), requestBody);
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
		if(headerList.get(0) != null) {
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
					repeatRequest(httpService, modifiedMessage);
				}
			}
		}	
	}
	
	private void doHeaderModifications(IRequestInfo requestInfo, IHttpService httpService, byte[] requestBody) {
		for(String header : headerList) {
			List<String> requestHeaders = requestInfo.getHeaders();
			requestHeaders.add(header);
			byte[] modifiedMessage = BurpExtender.callbacks.getHelpers().buildHttpMessage(requestHeaders, requestBody);
			BurpExtender.callbacks.printOutput(("Request (Header): " + header));
			repeatRequest(httpService, modifiedMessage);
		}
	}

	private void repeatRequest(IHttpService httpService, byte[] request) {
		threadPool.execute(new Runnable() {
			
			@Override
			public void run() {					
				IHttpRequestResponse requestResponse = BurpExtender.callbacks.makeHttpRequest(httpService, request);
				checkAndCreateIssue(requestResponse);
			}
		});
	}
	
	private void checkAndCreateIssue(IHttpRequestResponse requestResponse) {
		if(requestResponse.getResponse() != null) {
			IResponseInfo responseInfo = BurpExtender.callbacks.getHelpers().analyzeResponse(requestResponse.getResponse());
			for(int code : Settings.getForbiddenStatusCodes()) {
				if(responseInfo.getStatusCode() == code) {
					IScanIssue issue = new BypasserIssue(requestResponse);
					BurpExtender.callbacks.addScanIssue(issue);
				}
			}
		}
	}
	
}
