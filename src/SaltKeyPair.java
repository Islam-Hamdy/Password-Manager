import java.math.BigInteger;
import java.util.Arrays;

public class SaltKeyPair {
	private byte[] sk;
	private byte[] salt;

	public SaltKeyPair(byte[] aSalt, byte[] aSk) {
		sk = aSk;
		salt = aSalt;
	}

	public SaltKeyPair(String s) {
		String[] splitted = s.split(":");
		salt = fromHex(splitted[0]);
		sk = fromHex(splitted[1]);
	}

	public byte[] getKey() {
		return copyData(sk);
	}

	public byte[] getSalt() {
		return copyData(salt);
	}

	private byte[] copyData(byte[] data) {

		byte[] b = Arrays.copyOf(data, data.length);
		return b;
	}

	private byte[] fromHex(String s) {
		int sz = s.length() / 2;
		byte[] b = new byte[sz];
		for (int i = 0; i < sz; ++i)
			b[i] = (byte) Integer.parseInt(s.substring(2 * i, 2 * i + 2), 16);
		return b;
	}

	public String toString() {
		BigInteger bi = new BigInteger(1, salt);
		String hex = bi.toString(16);
		int paddingLength = (salt.length * 2) - hex.length();
		if (paddingLength > 0) {
			hex = String.format("%0" + paddingLength + "d", 0) + hex;
		}

		bi = new BigInteger(1, sk);
		String hex2 = bi.toString(16);
		paddingLength = (sk.length * 2) - hex2.length();
		if (paddingLength > 0) {
			hex2 = String.format("%0" + paddingLength + "d", 0) + hex2;
		}

		return hex + ':' + hex2;
	}

}
