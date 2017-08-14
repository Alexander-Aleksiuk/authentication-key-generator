package by.sandbox.tools;

import java.io.UnsupportedEncodingException;

import static java.lang.System.err;
import static java.lang.System.out;

/**
 * Created by Aliaksandr_Aleksiuk on 7/25/2017.
 */
public class AuthenticationKeyGenerator {
	public static void main(String[] args) throws UnsupportedEncodingException {
		if (args.length < 1) {
			err.println("Secret should be specified");
			return;
		}

		new AuthenticationKeyGenerator().run(args[0]);
	}

	private void run(String secret) throws UnsupportedEncodingException {
		out.println(new Authenticator().getAuthenticationKey(secret));
	}
}