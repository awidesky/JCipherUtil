package io.github.awidesky.jCipherUtil.key.keyExchange.ecdh;

/**
 * Available Elliptic curves for ECDH Key exchange algorithm.<p>
 * <a href=https://docs.oracle.com/en/java/javase/17/docs/specs/security/standard-names.html#parameterspec-names>
 * https://docs.oracle.com/en/java/javase/17/docs/specs/security/standard-names.html#parameterspec-names<a>
 */
public enum ECDHCurves {

	secp256r1,
	secp384r1,
	secp521r1;
	
}
