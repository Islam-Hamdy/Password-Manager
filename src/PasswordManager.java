

public class PasswordManager {
	

	private MasterPassManager mpm;
	private SavedPasswordManager passMan;
	
	public PasswordManager()
	{
		mpm = new MasterPassManager();
		mpm .createAccount("masterPassword");
		
		passMan = new SavedPasswordManager(mpm.getFirstKey(), mpm.getSecondKey());
		passMan.add("facebook", "facebookPass");
	}
	
	
	public static void main(String[] args) {
	
		
	}

}
