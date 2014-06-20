import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.KeySpec;

import javax.crypto.SecretKeyFactory;
import javax.crypto.interfaces.PBEKey;
import javax.crypto.spec.PBEKeySpec;


public class PasswordManager {
	
//	public void savePassword(String domain, String pass){
//		
//	}
//	
//	public byte[] genSalt() throws NoSuchAlgorithmException{
//		SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
//        byte[] salt = new byte[SALT_SIZE/8];
//        sr.nextBytes(salt);
//        return salt;
//	}
//	
//	public void genKeys(String password) throws NoSuchAlgorithmException{
//		SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("PBKDF2");
//		byte[] salt = genSalt();
//		KeySpec keySpec = new PBEKeySpec(password.toCharArray(), salt, PBKDF2_ITERATIONS, KEY_SIZE);
//		PBEKey encryptionKey = 
//	}
	
	private MasterPassManager mpm;
	public PasswordManager()
	{
		mpm = new MasterPassManager();
	}
	
	
	public static void main(String[] args) {
	
		
	}

}
