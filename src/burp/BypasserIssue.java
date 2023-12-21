package burp;

import java.net.URL;
public class BypasserIssue implements IScanIssue {

	private final String host;
	private final URL url;
	private final IHttpRequestResponse[] httpMessages;
	private final IHttpService httpService;
	private final int port;
	private final String protocol;
	public static final String ISSUE_NAME = "Bypass";
	
	public BypasserIssue(IHttpRequestResponse requestResponse) {
		IRequestInfo requestInfo = BurpExtender.callbacks.getHelpers().analyzeRequest(requestResponse.getRequest());
		this.host = requestResponse.getHttpService().getHost();
		this.url = requestInfo.getUrl();
		this.httpMessages = new IHttpRequestResponse[] {requestResponse};
		this.httpService = requestResponse.getHttpService();
		this.port = requestResponse.getHttpService().getPort();
		this.protocol = requestResponse.getHttpService().getProtocol();
	}
	
	public String getConfidence() {
		return "Certain";
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
		return "Information";
	}

	public String getIssueBackground() {
		return "A cross request indicates that a request was performed from one origin to a different origin. This can be for instance to"
				+ " a Cross Domain Script include or a Cross Domain Referer Leakage.";
	}

	public String getRemediationBackground() {
		return "Cross domain requests should be avoided if possible.";
	}

	public String getIssueDetail() {
		return null;
	}

	public String getRemediationDetail() {
		return null;
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