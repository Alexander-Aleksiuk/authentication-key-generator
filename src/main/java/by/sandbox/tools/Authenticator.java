package by.sandbox.tools;

import org.apache.commons.codec.binary.Base32;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.UnsupportedEncodingException;
import java.util.concurrent.TimeUnit;

/**
 * Created by Aliaksandr_Aleksiuk on 7/25/2017.
 */
public class Authenticator {
	private final String HMAC_HASH = "HmacSHA1";
	private final int codeDigits = 6;
	private final int keyModulus = (int) Math.pow(10, codeDigits);
	private final long timeStepSizeInMillis = TimeUnit.SECONDS.toMillis(30);

	public String getAuthenticationKey(String secret) throws UnsupportedEncodingException {
		byte[] decodedSecret = new Base32().decode(secret);
		long time = System.currentTimeMillis();
		return String.valueOf(calculateCode(decodedSecret, getTimeWindowFromTime(time)));
	}

	private long getTimeWindowFromTime(long time) {
		return time / timeStepSizeInMillis;
	}

	/**
	* Calculates the verification code of the provided key at the specified
	* instant of time using the algorithm specified in RFC 6238.
	*
	* @param key the secret key in binary format.
	* @param tm  the instant of time.
	* @return the validation code for the provided key at the specified instant
	* of time.
	*/
	private int calculateCode(byte[] key, long tm) {
		// Allocating an array of bytes to represent the specified instant
		// of time.
		byte[] data = new byte[8];
		long value = tm;

		// Converting the instant of time from the long representation to a
		// big-endian array of bytes (RFC4226, 5.2. Description).
		for (int i = 8; i-- > 0; value >>>= 8) {
			data[i] = (byte) value;
		}

		// Building the secret key specification for the HmacSHA1 algorithm.
		SecretKeySpec signKey = new SecretKeySpec(key, HMAC_HASH);

		try {
			// Getting an HmacSHA1/HmacSHA256 algorithm implementation from the JCE.
			Mac mac = Mac.getInstance(HMAC_HASH);

			// Initializing the MAC algorithm.
			mac.init(signKey);

			// Processing the instant of time and getting the encrypted data.
			byte[] hash = mac.doFinal(data);

			// Building the validation code performing dynamic truncation
			// (RFC4226, 5.3. Generating an HOTP value)
			int offset = hash[hash.length - 1] & 0xF;

			// We are using a long because Java hasn't got an unsigned integer type
			// and we need 32 unsigned bits).
			long truncatedHash = 0;

			for (int i = 0; i < 4; ++i) {
				truncatedHash <<= 8;

				// Java bytes are signed but we need an unsigned integer:
				// cleaning off all but the LSB.
				truncatedHash |= (hash[offset + i] & 0xFF);
			}

			// Clean bits higher than the 32nd (inclusive) and calculate the
			// module with the maximum validation code value.
			truncatedHash &= 0x7FFFFFFF;
			truncatedHash %= keyModulus;

			// Returning the validation code to the caller.
			return (int)truncatedHash;
		} catch (Exception ex) {
			ex.printStackTrace();
			return 0;
		}
	}
}