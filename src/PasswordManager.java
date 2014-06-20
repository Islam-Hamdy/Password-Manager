import java.security.Security;


public class PasswordManager {

	private MasterPassManager mpm;
	private SavedPasswordManager passMan;

	public PasswordManager() {
		mpm = new MasterPassManager();
		mpm.createAccount("masterPassword");

		passMan = new SavedPasswordManager(mpm.getFirstKey(), mpm.getSecondKey());
		passMan.add("facebook", "facebookPass");
		System.out.println(passMan.get("facebook"));
	}

	public static void main(String[] args) {

		MasterPassManager mpm;
		SavedPasswordManager passMan;
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
		mpm = new MasterPassManager();
		mpm.createAccount("masterPassword");

		passMan = new SavedPasswordManager(mpm.getFirstKey(), mpm.getSecondKey());
		passMan.add("facebook", "facebookPass");
		System.out.println(passMan.get("facebook"));


	}

}
