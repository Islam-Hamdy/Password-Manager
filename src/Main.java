import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.Security;
import java.util.Map;
import java.util.Scanner;
import java.util.StringTokenizer;

public class Main {
	static MasterPassManager mpm;
	static SavedPasswordManager passMan;

	public static void main(String[] args) throws IOException {
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

		mpm = new MasterPassManager();

		Scanner s = new Scanner(System.in);
		System.out.println("Enter your Master Pass : ");
		String pass = s.nextLine();
		s.close();

		boolean validLogin = mpm.login(pass);
		if (!validLogin) {
			mpm.createAccount(pass);
			System.out.println("Account Created");
		} else {
			System.out.println("Valid pass");
		}

		passMan = new SavedPasswordManager(mpm.getFirstKey(),
				mpm.getSecondKey());

		if (validLogin)
			loadMaps();

		parseInput();
		flushSerializedData();

	}

	// add <domain_name> <password>
	// set <domain_name> <password>
	// get <domain_name>
	// remove <domain_name>
	private static void parseInput() throws IOException {
		StringTokenizer st;
		String input = "";
		BufferedReader buff = new BufferedReader(new InputStreamReader(
				System.in));
		while ((input = buff.readLine()) != null) {
			st = new StringTokenizer(input);
			String command = st.nextToken();
			String domainName = st.nextToken();
			String password = "";

			switch (command) {
			case "add":
				password = st.nextToken();
				passMan.add(domainName, password);
				System.out.println("Domain (" + domainName + "), pass = \""
						+ password + "\" Added successfully !");
				break;
			case "set":
				password = st.nextToken();
				passMan.set(domainName, password);
				System.out.println("Domain (" + domainName + "), pass = \""
						+ password + "\" Updated successfully !");
				break;
			case "get":
				System.out.println("Domain (" + domainName + "), pass = \""
						+ passMan.get(domainName) + "\"");
				break;
			case "remove":
				password = st.nextToken();
				passMan.remove(domainName, password);
				System.out.println("Domain (" + domainName + "), pass = \""
						+ password + "\" Removed successfully !");
				break;
			}
		}
		buff.close();
	}

	@SuppressWarnings("unchecked")
	private static void loadMaps() {

		// Loading domain_pass_map from the serialized file
		try {
			FileInputStream fis = new FileInputStream("domain_pass_map.ser");
			ObjectInputStream ois = new ObjectInputStream(fis);
			passMan.domainPassMap = (Map<String, byte[]>) ois.readObject();
			ois.close();
			fis.close();
		} catch (IOException ioe) {
			ioe.printStackTrace();
			return;
		} catch (ClassNotFoundException c) {
			c.printStackTrace();
			return;
		}

		// Loading domain_salt_map from the serialized file
		try {
			FileInputStream fis = new FileInputStream("domain_salt_map.ser");
			ObjectInputStream ois = new ObjectInputStream(fis);
			passMan.domainSaltMap = (Map<String, byte[]>) ois.readObject();
			ois.close();
			fis.close();
		} catch (IOException ioe) {
			ioe.printStackTrace();
			return;
		} catch (ClassNotFoundException c) {
			c.printStackTrace();
			return;
		}

		// Loading pass_iv_map from the serialized file
		try {
			FileInputStream fis = new FileInputStream("pass_iv_map.ser");
			ObjectInputStream ois = new ObjectInputStream(fis);
			passMan.passIVMap = (Map<String, byte[]>) ois.readObject();
			ois.close();
			fis.close();
		} catch (IOException ioe) {
			ioe.printStackTrace();
			return;
		} catch (ClassNotFoundException c) {
			c.printStackTrace();
			return;
		}

		// Loading swap_attack_map from the serialized file
		try {
			FileInputStream fis = new FileInputStream("swap_attack_map.ser");
			ObjectInputStream ois = new ObjectInputStream(fis);
			passMan.swapAttackBlocker = (Map<String, byte[]>) ois.readObject();
			ois.close();
			fis.close();
		} catch (IOException ioe) {
			ioe.printStackTrace();
			return;
		} catch (ClassNotFoundException c) {
			c.printStackTrace();
			return;
		}
	}

	/**
	 * Flush out manager's necessary maps to retrieve domain-pass data later
	 */
	private static void flushSerializedData() {

		// Flush domain_pass to a serialized file
		try {
			FileOutputStream fos = new FileOutputStream("domain_pass_map.ser");
			ObjectOutputStream oos = new ObjectOutputStream(fos);
			oos.writeObject(passMan.domainPassMap);
			oos.close();
			fos.close();
		} catch (IOException ioe) {
			ioe.printStackTrace();
		}

		// Flush domain_salt to a serialized file
		try {
			FileOutputStream fos = new FileOutputStream("domain_salt_map.ser");
			ObjectOutputStream oos = new ObjectOutputStream(fos);
			oos.writeObject(passMan.domainSaltMap);
			oos.close();
			fos.close();
		} catch (IOException ioe) {
			ioe.printStackTrace();
		}

		// Flush pass_iv to a serialized file
		try {
			FileOutputStream fos = new FileOutputStream("pass_iv_map.ser");
			ObjectOutputStream oos = new ObjectOutputStream(fos);
			oos.writeObject(passMan.passIVMap);
			oos.close();
			fos.close();
		} catch (IOException ioe) {
			ioe.printStackTrace();
		}

		// Flush swap_attack map to a serialized file
		try {
			FileOutputStream fos = new FileOutputStream("swap_attack_map.ser");
			ObjectOutputStream oos = new ObjectOutputStream(fos);
			oos.writeObject(passMan.swapAttackBlocker);
			oos.close();
			fos.close();
		} catch (IOException ioe) {
			ioe.printStackTrace();
		}
	}
}
