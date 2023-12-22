package burp;

public class Settings {
	
	private static short[] forbiddenStatusCodes = new short[] {403,401};
	
	public static void setForbiddenStatusCodes(short[] forbiddenStatusCodes) {
		Settings.forbiddenStatusCodes = forbiddenStatusCodes;
	}
	
	public static short[] getForbiddenStatusCodes() {
		return forbiddenStatusCodes;
	}

}
