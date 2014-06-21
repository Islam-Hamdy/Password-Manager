import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;


public class SavedPasswordManager {

	// based on GCM/AES
	final int BLOCK_LEN = 128; // in bits
	final int SALT_LEN = 128; // in bits
	final int PASS_TAG_LEN = 128; // in bits
	final int DOMAIN_TAG_LEN = 256; // in bits using SHA256
	final int IV_LEN = 128; // in bits
	final int PASS_LEN = 128; // in bytes
	final int SWAP_BLOCK_TUPLE_LEN = 2*DOMAIN_TAG_LEN/8; // in bytes 

	final String MAC_ALGORITHM = "HmacSHA256";
	final String ENCRYPTION_ALGORITHM = "AES";
	final String RANDOM_ALGORITHM = "SHA1PRNG";

	SecureRandom secureRand;
	SecretKeySpec encryptionKeySpec;
	SecretKeySpec MACKeySpec; // TODO: ask ?? encrypt all passwords with the same key

	Map<String, byte[]> domainPassMap = new HashMap<String, byte[]>();
	Map<String, byte[]> passIVMap = new HashMap<String, byte[]>();
	Map<String, byte[]> domainSaltMap = new HashMap<String, byte[]>();

	Map<String, byte[]> swapAttackBlocker = new HashMap<String, byte[]>();
	// contains mapping between domain tags and chosen subset of the encryptedpass||domain   

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
		byte[] passwordEncrypted = null, domainTag;
		String domainTagString="";
		try {

			domainTagString = new String(domainTag = MACDomain(domain));

			// generate random salt, save the salt related to the domainTag, and pad the the password after adding the salt
			byte [] salt = new byte[SALT_LEN/8];
			secureRand.nextBytes(salt);
			domainSaltMap.put(domainTagString, salt);
			byte[] paddedPass = saltAndPad(domainTagString, password, salt);
			passwordEncrypted = encryptPassword(paddedPass);

			byte[] swapBlockerPair = makeSwapBlockPair(domainTag, passwordEncrypted);
			swapAttackBlocker.put(domainTagString, swapBlockerPair);
		} catch (Exception e) {
			e.printStackTrace();
		}

		if (domainPassMap.containsKey(domainTagString))
			throw new IllegalArgumentException("domain already bound");

		domainPassMap.put(domainTagString, passwordEncrypted);
	}

	/**
	 * @param domain 
	 * @return saved password bound with that domain
	 * 		   null of swapAttack detected
	 */
	public String get(String domain){
		byte[] domainTag = null;
		String plainPass = "" ;
		try {
			domainTag = MACDomain(domain);
		} catch (NoSuchAlgorithmException | InvalidKeyException e){
			e.printStackTrace();
		}

		String domainTagString = new String (domainTag);
		if (!domainPassMap.containsKey(domainTagString))
			throw new IllegalArgumentException("domain not found");

		byte [] passwordEncrypted = domainPassMap.get(domainTagString);

		boolean swapAttack = false;
		try{
			// check for swap attacks
			byte[] swapAttackPair = makeSwapBlockPair(domainTag, passwordEncrypted);
			byte[] savedSwapPair = swapAttackBlocker.get(domainTag);

			for (int i = 0; i < savedSwapPair.length && !swapAttack; i++) 
				if (swapAttackPair[i] != savedSwapPair[i])
					swapAttack = true;
			
			if (swapAttack)
				return null;
			
			byte[] paddedPass = decryptPassword(passwordEncrypted);
			plainPass = new String(removePadAndSalt(paddedPass));
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
				domainTag = MACDomain(domain);
				String domainTagString = new String(domainTag);

				// generate random salt, save the salt related to the domainTag, and pad the the password after adding the salt
				byte [] salt = new byte[SALT_LEN/8]; // generate new salt with the new password
				secureRand.nextBytes(salt);
				domainSaltMap.put(domainTagString, salt); // updating the salt in the map
				byte[] paddedPass = saltAndPad(domainTagString, newPassword, salt);

				passwordEncrypted = encryptPassword(paddedPass);
				domainPassMap.put(domainTagString, passwordEncrypted);
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
			String domainTagString;
			try {
				domainTagString = new String(MACDomain(domain));
				domainPassMap.remove(domainTagString);
			} catch (NoSuchAlgorithmException | InvalidKeyException e) {
				e.printStackTrace();
			}
		}
	}



	/**
	 * @param domainTag
	 * @param encryptedPass
	 * @return MAC tag for the "domainTag"||"encryptedPass(first 128bit)" 
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeyException
	 */
	private byte[] makeSwapBlockPair(byte[] domainTag, byte[] encryptedPass) throws NoSuchAlgorithmException, InvalidKeyException{
		byte [] data = Arrays.copyOf(domainTag, SWAP_BLOCK_TUPLE_LEN);
		System.arraycopy(encryptedPass, 0, data, domainTag.length, SWAP_BLOCK_TUPLE_LEN-DOMAIN_TAG_LEN/8);

		Mac HMAC = Mac.getInstance(MAC_ALGORITHM);
		HMAC.init(MACKeySpec);
		return HMAC.doFinal(data);  
	}

	/**
	 * @param domain
	 * @param password
	 * @return true if the given domain and password saved in the system
	 * 		   false if domain no found, domain coupled with other password
	 */
	private boolean verify(String domain, String password){
		byte [] passwordEncrypted, domainTag;
		String domainTagString ;
		try {
			domainTagString = new String(domainTag = MACDomain(domain));

			//fetch tag from map 
			if (!domainSaltMap.containsKey(domainTagString))
				return false;
			byte[] salt = domainSaltMap.get(domainTagString);

			byte[] paddedPass = saltAndPad(domainTagString, password, salt);
			passwordEncrypted = encryptPassword(paddedPass);
			if (!domainPassMap.containsKey(domainTagString))
				return false;

			if (!passwordEncrypted.equals(domainPassMap.get(domainTagString)))
				return false;

			// check for swap atacks 
			byte[] swapAttackPair = makeSwapBlockPair(domainTag, passwordEncrypted);
			byte[] savedSwapPair = swapAttackBlocker.get(domainTag);


			for (int i = 0; i < savedSwapPair.length; i++) 
				if (swapAttackPair[i] != savedSwapPair[i])
					return false;

		} catch (Exception e){
			e.printStackTrace();
		}
		return true;
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
		byte[] tag = HMAC.doFinal(domain.getBytes());
		return tag;
	}


	/**
	 * @param pass
	 * @return byte[] of the password after being padded into a PAD_LENGTH byte[]
	 * NOTE: not used right now since GCM padds the password ..
	 */
	private byte[] saltAndPad(String domainTag, String pass, byte[] salt){
		byte[] saltedPass = Arrays.copyOf(pass.getBytes(), pass.length()+salt.length);
		System.arraycopy(salt, 0, saltedPass, pass.length(), salt.length);

		//		if (pass.length() >= PASS_LEN)
		//			throw new IllegalArgumentException("passwords should be smaller than padded size");
		byte[] paddedPass = Arrays.copyOf(saltedPass, PASS_LEN);
		byte pad = (byte) (paddedPass.length - saltedPass.length);
		Arrays.fill(paddedPass, saltedPass.length, PASS_LEN, pad);
		return paddedPass;
	}

	/**
	 * @param paddedPass
	 * @return the clean encrypted password after removing the pad and the salt
	 */
	private byte[] removePadAndSalt(byte[] paddedPass){
		int padSize = paddedPass[paddedPass.length-1];
		return Arrays.copyOfRange(paddedPass, 0, paddedPass.length - padSize - SALT_LEN/8);
	}

	/**
	 * @param password
	 * @return the encryption of the password using GCM mode of operation
	 * @throws Exception
	 */
	private byte[] encryptPassword(byte[] paddedPassword) throws Exception{
		byte[] IV = new byte[IV_LEN/8];
		secureRand.nextBytes(IV);
		// TODO try to change noPadding here 
		Cipher gcm = Cipher.getInstance("AES/GCM/NoPadding", "BC");
		GCMParameterSpec GCMspec = new GCMParameterSpec(PASS_TAG_LEN, IV);

		gcm.init(Cipher.ENCRYPT_MODE, encryptionKeySpec, GCMspec);
		byte[] tag = gcm.doFinal(paddedPassword);
		passIVMap.put(new String(tag), IV); //  bind IV to current cipherText
		return tag;
	}

	/**
	 * @param password
	 * @return the plaintext password
	 * @throws Exception 
	 */
	private byte[] decryptPassword(byte[] passwordTag) throws Exception{
		// TODO try to change noPadding here 
		Cipher gcm = Cipher.getInstance("AES/GCM/NoPadding", "BC");
		String passwordTagString = new String(passwordTag);
		if (!passIVMap.containsKey(passwordTagString))
			throw new IllegalArgumentException("password not found");

		byte[] IV = passIVMap.get(passwordTagString);

		GCMParameterSpec GCMspec = new GCMParameterSpec(PASS_TAG_LEN, IV);

		gcm.init(Cipher.DECRYPT_MODE, encryptionKeySpec, GCMspec);
		byte[] plainPass = gcm.doFinal(passwordTag);

		return plainPass;
	}
}
