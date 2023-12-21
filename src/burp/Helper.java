package burp;

public class Helper {

	public static boolean isSameDomain(String host1, String host2) {
		String[] host1Split = host1.split("\\.");
		String[] host2Split = host2.split("\\.");
		if(host1Split.length > 1 && host2Split.length > 1) {
			String topLevelHost1 = host1Split[host1Split.length-1];
			String secondLevelHost1 = host1Split[host1Split.length-2];
			String topLevelHost2 = host2Split[host2Split.length-1];
			String secondLevelHost2 = host2Split[host2Split.length-2];
			if(topLevelHost1.equals(topLevelHost2) && secondLevelHost1.equals(secondLevelHost2)) {
				return true;
			}
		}
		return false;
	}
	
}
