package burp;

public class Settings {
	
	private static short[] forbiddenStatusCodes = new short[] {4,5};
	private static long dealayBetweenRequests = 100;
	
	public static void setForbiddenStatusCodes(short[] forbiddenStatusCodes) {
		Settings.forbiddenStatusCodes = forbiddenStatusCodes;
	}
	
	public static short[] getForbiddenStatusCodes() {
		return forbiddenStatusCodes;
	}

	public static long getDealayBetweenRequests() {
		return dealayBetweenRequests;
	}

	public static void setDealayBetweenRequests(long dealayBetweenRequests) {
		Settings.dealayBetweenRequests = dealayBetweenRequests;
	}

}
