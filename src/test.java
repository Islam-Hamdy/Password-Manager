import java.util.Scanner;

public class test {

public static void main(String[] args) {
	MasterPassManager mpm = new MasterPassManager();
	
	Scanner s = new Scanner(System.in);
	System.out.println("Enter your Master Pass : ");
	String pass = s.nextLine();
	mpm .createAccount(pass);
	System.out.println("Account Created");
	
	System.out.println("try logining in");
	System.out.println("Enter your Master Pass :");
	pass = s.nextLine();
	
	if(mpm.login(pass))
	{
		System.out.println("Valid pass");
	}
	else
	{
		System.out.println("invalid pass");
	}
	
	s.close();
}	
}
