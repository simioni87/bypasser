package burp;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Properties;

public class BurpExtender implements IBurpExtender {

	public static IBurpExtenderCallbacks callbacks;

	@Override
	public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
		BurpExtender.callbacks = callbacks;
		callbacks.setExtensionName(Globals.EXTENSION_NAME);

		File patternFile = new File("patterns.txt");
		File headerFile = new File("headers.txt");
		File settingsFile = new File("settings.txt");
		if (!patternFile.exists() || !patternFile.exists() || !settingsFile.exists()) {
			callbacks.printOutput("Needed Lists not found:");
			callbacks.printOutput(System.getProperty("user.dir") + "\\" + patternFile.getName());
			callbacks.printOutput(System.getProperty("user.dir") + "\\" + headerFile.getName());
			callbacks.printOutput(System.getProperty("user.dir") + "\\" + settingsFile.getName());
			callbacks.printOutput("Example Lists can be found here:");
			callbacks.printOutput("https://github.com/simioni87/bypasser/tree/main/lists");
			callbacks.unloadExtension();
		} else {
			callbacks.printOutput("Pattern List Loaded: " + patternFile.getAbsolutePath());
			callbacks.printOutput("Header List Loaded: " + headerFile.getAbsolutePath());
			callbacks.printOutput("Settings Loaded: " + settingsFile.getAbsolutePath());
			callbacks.printOutput(Globals.EXTENSION_NAME + " successfully started...");
			callbacks.printOutput("Version " + Globals.VERSION);
			readSettings(settingsFile);
			callbacks.registerContextMenuFactory(
					new ContextMenuController(getPatternMap(patternFile), getHeaderList(headerFile)));
		}
	}

	private ArrayList<String> getHeaderList(File file) {
		ArrayList<String> list = new ArrayList<>();
		BufferedReader reader;
		try {
			reader = new BufferedReader(new FileReader(file));
			String line = reader.readLine();
			while (line != null) {
				// Do not care about empty lines and comments
				if (!line.trim().startsWith("#") && !line.trim().equals("")) {
					list.add(line);
					line = reader.readLine();
				}
			}
			reader.close();
		} catch (IOException e) {
			BurpExtender.callbacks.printError(e.getMessage());
		}
		return list;
	}

	private HashMap<String, ArrayList<String>> getPatternMap(File file) {
		HashMap<String, ArrayList<String>> patternMap = new HashMap<>();
		BufferedReader reader;
		try {
			reader = new BufferedReader(new FileReader(file));
			String line = reader.readLine();
			String currentRule = null;
			while (line != null) {
				if (line.trim().startsWith("#")) {
					if(line.startsWith("#RULE_")) {
						currentRule = line.split(":")[0].replace("#", "");
					}
				} else {
					if (currentRule == null) {
						callbacks.printOutput("Something is wrong with your pattern file. Use following syntax:\n"
								+ "#RULE_1: Any_text\n" + "pattern1\n" + "patternx");
					} else if (!line.trim().equals("")) {
						if (patternMap.get(currentRule) == null) {
							patternMap.put(currentRule, new ArrayList<>());
						}
						patternMap.get(currentRule).add(line);
					}
				}
				line = reader.readLine();
			}
			reader.close();
		} catch (IOException e) {
			BurpExtender.callbacks.printError(e.getMessage());
		}
		return patternMap;
	}

	private void readSettings(File file) {
		try (InputStream input = new FileInputStream(file)) {
			Properties prop = new Properties();
			prop.load(input);
			
			//Read forbidden status codes
			String forbiddenStatusCodes = prop.getProperty("forbiddenStatusCodes");
			if(forbiddenStatusCodes != null) {
				List<Short> codeList = new ArrayList<>();
				for(String statusCode : forbiddenStatusCodes.split(",")) {
					codeList.add(Short.parseShort(statusCode));
				}
				short[] codeArray = new short[codeList.size()];
				for(int i=0; i<codeList.size(); i++) {
					codeArray[i] = codeList.get(i);
				}
				Settings.setForbiddenStatusCodes(codeArray);
			}
			String delayBetweenRequests = prop.getProperty("delayBetweenRequests");
			if(delayBetweenRequests != null) {
				Settings.setDealayBetweenRequests(Long.parseLong(delayBetweenRequests));
			}

		} catch (IOException ex) {
			callbacks.printError(ex.getMessage());
		}
	}
}
