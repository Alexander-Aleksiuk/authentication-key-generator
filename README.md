# TOTP authentication key generator
TOTP authentication key generator can be used to obtain authentication key from command line using secret key provided for Two-factor authentication.

Calculates the verification code of the provided key at the specified instant of time using the algorithm specified in [RFC 6238](https://tools.ietf.org/html/rfc6238).

The Time-Step Size is hardcoded for 30 seconds.

# Usage:
```
java -jar authentication-key-generator.jar SECRET_KEY
```

**Input parameter:** secret key

**Output parameter:** authentication key
