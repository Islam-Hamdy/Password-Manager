import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import javax.crypto.KeyGenerator;

public class Main {
	public static void main(String[] args) throws NoSuchAlgorithmException {
		String masterPassword = "DES";
		System.out.println(Arrays.toString(KeyGenerator.getInstance(masterPassword).generateKey().getEncoded()));
	}
}
