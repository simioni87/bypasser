package burp;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Set;

public class PathModifier {

	public static HashSet<String> applyAllRules(String path, HashMap<String,ArrayList<String>> patternMap) {
		HashSet<String> pathSet = new HashSet<String>();
		
		applyRule1(path, pathSet, patternMap.get("RULE_1"));
		applyRule2(path, pathSet, patternMap.get("RULE_2"));
		applyRule3(path, pathSet, patternMap.get("RULE_3"));
		applyRule4(path, pathSet, patternMap.get("RULE_4"));
		
		return pathSet;
	}
	
	
	/*
	 * Rule 1: Replace last slash with (e.g.: /a/b/c -> /a/b%2fc)
	 */
	public static void applyRule1(String path, Set<String> pathSet, ArrayList<String> patterns) {
		//String[] patterns = new String[] {"%2e", "%2e%2e", "%5c", "%2f", "../", "\\"};
		for(String pattern : patterns) {
			int index = path.lastIndexOf("/");
			if(index != -1) {
				String newPath = path.substring(0, index) + pattern + path.substring(index+1);
				pathSet.add(newPath);				
			}
		}
	}
	
	/*
	 * Rule 2: Append at the end: (e.g.: /a/b/c -> /a/b/c/.)
	 */
	public static void applyRule2(String path, Set<String> pathSet, ArrayList<String> patterns) {
		//String[] patterns = new String[] {"/.", "%20/", "?", "???", "//", "/", "..;/"};
		for(String pattern : patterns) {
			String newPath = path + pattern;
			pathSet.add(newPath);
		}
	}
	
	/*
	 * Rule 3: Match and Replace Slash - With and Without an appended Slash (e.g.: /a/b/c -> \a\b\c AND \a\b\c\)
	 */
	public static void applyRule3(String path, Set<String> pathSet, ArrayList<String> patterns) {
		//String[] patterns = new String[] {"\\", "%2f", "%5c", "//", "/./"};
		for(String pattern : patterns) {
			String newPath = path.replace("/", pattern);
			pathSet.add(newPath);
			//And with appended slash
			String modifPath = path + "/";
			String newPath1 = modifPath.replace("/", pattern);
			pathSet.add(newPath1);
		}
	}
	
	/*
	 * Rule 4: Append at any path element (e.g. /a/b/c -> /a;a=b/b/c/ AND /a/b;a=b/c/ AND /a/b/c;a=b/)
	 */
	public static void applyRule4(String path, Set<String> pathSet, ArrayList<String> patterns) {
		//String[] patterns = new String[] {";a=b", "../"};
		for(String pattern : patterns) {
			
			int numberOfSlashes = 0;
			int beginIndex = path.indexOf("/");
			int endIndex = path.indexOf("/", beginIndex);
			while(beginIndex != path.length()) {
				numberOfSlashes++;
				String newPath = path.substring(0, endIndex) + pattern + path.substring(endIndex, path.length());
				beginIndex = endIndex;
				endIndex = path.indexOf("/", beginIndex+1);
				if(endIndex == -1) {
					endIndex = path.length();
				}
				if(numberOfSlashes != 1) {
					pathSet.add(newPath);
				}	
			}
		}
	}	
}
