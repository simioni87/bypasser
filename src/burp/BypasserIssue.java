package burp;

import java.net.MalformedURLException;
import java.net.URL;
public class BypasserIssue implements IScanIssue {

	private final String host;
	private URL url;
	private final IHttpRequestResponse[] httpMessages;
	private final IHttpService httpService;
	private final int port;
	private final String protocol;
	public final String message;
	public static final String ISSUE_NAME = "Bypass";
	
	public BypasserIssue(IHttpRequestResponse requestResponse, String message) {
		IRequestInfo requestInfo = BurpExtender.callbacks.getHelpers().analyzeRequest(requestResponse);
		this.host = requestResponse.getHttpService().getHost();
		this.url = requestInfo.getUrl();
		this.httpMessages = new IHttpRequestResponse[] {requestResponse};
		this.httpService = requestResponse.getHttpService();
		this.port = requestResponse.getHttpService().getPort();
		this.protocol = requestResponse.getHttpService().getProtocol();
		this.message = message;
	}
	
	public String getConfidence() {
		return "Firm";
	}

	public String getHost() {
		return host;
	}

	public String getIssueName() {
		return ISSUE_NAME;
	}

	public int getIssueType() {
		return 0x08000000;
	}

	public String getSeverity() {
		return "High";
	}

	public String getIssueBackground() {
		return "A possible bypass of a forbidden resource was found.";
	}

	public String getRemediationBackground() {
		return "";
	}

	public String getIssueDetail() {
		return message;
	}

	public String getRemediationDetail() {
		return "Verify and fix the 403 Bypass.";
	}

	public IHttpRequestResponse[] getHttpMessages() {
		return httpMessages;
	}

	public IHttpService getHttpService() {
		return httpService;
	}

	public int getPort() {
		return port;
	}

	public String getProtocol() {
		return protocol;
	}

	@Override
	public URL getUrl() {
		return url;
	}
}