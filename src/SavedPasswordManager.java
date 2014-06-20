import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.TreeMap;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;


public class SavedPasswordManager {

	final int PASS_LEN = 64; //in bytes
	final int PASS_TAG_LEN = 128; // in bits
	final int DOMAIN_TAG_LEN = 256; //in bits using SHA256 
	final int IV_LEN = 64; // in bits
	
	final String MAC_ALGORITHM = "HmacSHA256";
	final String ENCRYPTION_ALGORITHM = "AES";
	final String RANDOM_ALGORITHM = "SHA1PRNG";
	
	SecureRandom secureRand;
	SecretKeySpec encryptionKeySpec;
	SecretKeySpec MACKeySpec; // TODO: ask ?? encrypt all passwords with the same key
	
	TreeMap<byte[], byte[]> domainPassMap = new TreeMap<byte[], byte[]>();
	TreeMap<byte[], byte[]> passIVMap = new TreeMap<byte[], byte[]>();
	
	public SavedPasswordManager(byte[] encryptKey, byte[] MACKey) {
		try {
			secureRand = SecureRandom.getInstance(RANDOM_ALGORITHM);
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		encryptionKeySpec = new SecretKeySpec(encryptKey, ENCRYPTION_ALGORITHM);
		MACKeySpec = new SecretKeySpec(MACKey, MAC_ALGORITHM);
	}	
	
	/**
	 * @param domain
	 * @param password
	 * adds new password to the system associated with the domain name
	 */
	public void add(String domain, String password){
		byte[] domainTag = null, passwordEncrypted = null;
		
		try {
			
			domainTag = MACDomain(domain);
			passwordEncrypted = encryptPassword(password);
		} catch (Exception e) {
			e.printStackTrace();
		}
		
		if (domainPassMap.containsKey(domainTag))
			throw new IllegalArgumentException("domain already bound");
		
		domainPassMap.put(domainTag, passwordEncrypted);
	}

	/**
	 * @param domain
	 * @return saved password bound with that domain
	 */
	public String get(String domain){
		byte[] domainTag = null;
		try {
			domainTag = MACDomain(domain);
		} catch (InvalidKeyException | NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		byte [] passwordEncrypted = domainPassMap.get(domainTag);
		String plainPass = "" ;
		
		try {
			plainPass = decryptPassword(passwordEncrypted);
		} catch (Exception e) {
			e.printStackTrace();
		}
		
		return plainPass;
	}

	
	
	/**
	 * @param domain
	 * @param oldPassword
	 * @param newPassword
	 * @return true if oldpass verifies and hence the operation was successful
	 * 		   false if oldpass failed to verify
	 * sets the the password associated with the domain name with the new password 
	 * after verifying the old password is correct.  
	 */
	public boolean set(String domain, String oldPassword, String newPassword){

		if (verify(domain, oldPassword)){
			byte[] passwordEncrypted, domainTag;
			try {
				passwordEncrypted = encryptPassword(newPassword);
				domainTag = MACDomain(domain);
				domainPassMap.put(domainTag, passwordEncrypted);
			} catch (Exception e) {
				e.printStackTrace();
			}
			return true;
		} else
			return false;
	}
	
	
	
	
	/**
	 * @param domain
	 * @param password
	 * removes the <domain,password> from the system after verifying the password
	 */
	public void remove(String domain, String password){
		if (verify(domain, password)){
			byte[] domainTag;
			try {
				domainTag = MACDomain(domain);
				domainPassMap.remove(domainTag);
			} catch (NoSuchAlgorithmException | InvalidKeyException e) {
				e.printStackTrace();
			}
		}
	}

	
	
	/**
	 * @param domain
	 * @param password
	 * @return true if the given domain and password saved in the system
	 * 		   false if domain no found, domain coupled with other password
	 */
	private boolean verify(String domain, String password){
		byte [] domainTag, passwordEncrypted;
		try {
			domainTag = MACDomain(domain);
			passwordEncrypted = encryptPassword(password);
			if (domainPassMap.containsKey(domainTag))
				return passwordEncrypted.equals(domainPassMap.get(domainTag)); 
		} catch (Exception e){
			e.printStackTrace();
		}
		return false;
	} 
	
	
	/**
	 * @param domain
	 * @return the tag resulted from MACing the domain
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeyException
	 */
	private byte[] MACDomain(String domain) throws NoSuchAlgorithmException, InvalidKeyException{
		Mac HMAC = Mac.getInstance(MAC_ALGORITHM);
		HMAC.init(MACKeySpec);
		byte[] tag = new byte[DOMAIN_TAG_LEN/8]; // we are using SHA 256
     	HMAC.doFinal(tag);
     	return tag;
	}
	
	/**
	 * @param pass
	 * @return byte[] of the password after being padded into a PAD_LENGTH byte[]
	 * NOTE: not used right now since GCM padds the password ..
	 */
	private byte[] pad(String pass){
//		if (pass.length() >= PASS_LEN)
//			throw new IllegalArgumentException("passwords should be smaller than padded size");
		
		byte[] paddedPass = Arrays.copyOf(pass.getBytes(), PASS_LEN);
		byte pad = (byte) (paddedPass.length - pass.length());
		Arrays.fill(paddedPass, pass.length(), PASS_LEN-1, pad);
			
		return paddedPass;
	}
	
	/**
	 * @param password
	 * @return the encryption of the password using GCM mode of operation
	 * @throws Exception
	 */
	private byte[] encryptPassword(String password) throws Exception{
		byte[] IV = new byte[IV_LEN/8];
		secureRand.nextBytes(IV);
		
		// TODO try to change noPadding here 
		Cipher eax = Cipher.getInstance("AES/EAX/NoPadding", "BC");
//		Cipher.getInstance("AES/CBC/PKCS5Padding");
		
		GCMParameterSpec GCMspec = new GCMParameterSpec(PASS_TAG_LEN, IV);
		
		if (eax.getBlockSize() != IV.length)
			System.err.println("IV and Cipher have different block size");
		
		eax.init(Cipher.ENCRYPT_MODE, encryptionKeySpec, GCMspec);
		byte[] tag = eax.doFinal(password.getBytes());
		passIVMap.put(tag, IV);
		return tag;
	}
	
	/**
	 * @param password
	 * @return the plaintext password
	 * @throws Exception 
	 */
	private String decryptPassword(byte[] password) throws Exception{
		// TODO try to change noPadding here 
		Cipher eax = Cipher.getInstance("AES/EAX/NoPadding", "BC");

		byte[] IV = passIVMap.get(password);
		GCMParameterSpec GCMspec = new GCMParameterSpec(PASS_TAG_LEN, IV);
		
		eax.init(Cipher.DECRYPT_MODE, encryptionKeySpec, GCMspec);
		byte[] plainPass = eax.doFinal(password);

		return new String(plainPass);
	}
}
