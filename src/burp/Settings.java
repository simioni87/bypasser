package burp;

public class Settings {
	
	private static int[] forbiddenStatusCodes = new int[] {403,401};
	
	public static void setForbiddenStatusCodes(int[] forbiddenStatusCodes) {
		Settings.forbiddenStatusCodes = forbiddenStatusCodes;
	}
	
	public static int[] getForbiddenStatusCodes() {
		return forbiddenStatusCodes;
	}

}
