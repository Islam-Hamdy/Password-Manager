import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;


public class KeyGen {
	
	public static final int SALT_SIZE = 64; // in bits
	public static final int KEY_SIZE = 128; // in bits
	public static final int PBKDF2_ITERATIONS = 1<<10;
	
	
	private String masterPwd;
	private SecureRandom sr;
	public KeyGen(String masterPass)  
	{
		masterPwd = masterPass;
		try {
			sr  = SecureRandom.getInstance("SHA1PRNG");
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
	}
	
	private byte[] getSalt()
	{
		byte [] b = new byte[SALT_SIZE/8];
		sr.nextBytes(b);
		return b;
	}
	public static byte[] getKey(byte [] aSalt, String password)
	{
		char[] chars = password.toCharArray();
	     byte[] salt = aSalt ;
	         
	     PBEKeySpec spec = new PBEKeySpec(chars, salt, PBKDF2_ITERATIONS, KEY_SIZE);
	     SecretKeyFactory skf;
		try {
			skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
			byte [] key = skf.generateSecret(spec).getEncoded();
			return  key;
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (InvalidKeySpecException e) {
			e.printStackTrace();
		}
		return null;
	}
	public SaltKeyPair generateKey() 
	{
	     char[] chars = masterPwd.toCharArray();
	     byte[] salt = getSalt();
	         
	     PBEKeySpec spec = new PBEKeySpec(chars, salt, PBKDF2_ITERATIONS, KEY_SIZE);
	     SecretKeyFactory skf;
		try {
			skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
			byte [] key = skf.generateSecret(spec).getEncoded();
			return new SaltKeyPair(salt, key);
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (InvalidKeySpecException e) {
			e.printStackTrace();
		}
		return null;
	}
	
}
