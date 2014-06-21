import java.io.File;
import java.io.FileNotFoundException;
import java.io.PrintWriter;
import java.util.Arrays;
import java.util.Scanner;

public class MasterPassManager {

	public static final String KEYSFILENAME = "keys";
	private byte[] key1;
	private byte[] key2;

	public byte[] getFirstKey() {
		return Arrays.copyOf(key1, key1.length);
	}

	public byte[] getSecondKey() {
		return Arrays.copyOf(key2, key2.length);
	}

	public void createAccount(String pass) {
		KeyGen kg = new KeyGen(pass);
		SaltKeyPair skp1 = kg.generateKey();
		SaltKeyPair skp2 = kg.generateKey();

		PrintWriter fs;
		try {
			fs = new PrintWriter(KEYSFILENAME);
			fs.println(skp1.toString());
			fs.println(skp2.toString());
			fs.flush();
			fs.close();
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		key1 = skp1.getKey();
		key2 = skp2.getKey();

	}

	public boolean login(String pass) {
		try {
			Scanner s = new Scanner(new File(KEYSFILENAME));
			String line = s.nextLine();
			SaltKeyPair skp1 = new SaltKeyPair(line);
			line = s.nextLine();
			SaltKeyPair skp2 = new SaltKeyPair(line);
			s.close();
			byte[] testkey1 = KeyGen.getKey(skp1.getSalt(), pass);
			byte[] testkey2 = KeyGen.getKey(skp2.getSalt(), pass);

			byte[] originalk1 = skp1.getKey();
			byte[] originalk2 = skp2.getKey();

			int diff1 = 0, diff2 = 0;
			int sz = testkey1.length;

			for (int i = 0; i < sz; ++i) {
				diff1 |= testkey1[i] ^ originalk1[i];
				diff2 |= testkey2[i] ^ originalk2[i];
			}

			if (diff1 == 0 && diff2 == 0) {
				key1 = originalk1;
				key2 = originalk2;
				return true;
			} else
				return false;

		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		return false;
	}

}
