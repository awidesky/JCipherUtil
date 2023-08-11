package io.github.awidesky.jCipherUtil.key.keyExchange.ecdh;

/**
 * Available Elliptic curves for ECDH Key exchange algorithm.
 * <a href=https://download.java.net/java/early_access/panama/docs/specs/security/standard-names.html#parameterspec-names>
 * https://download.java.net/java/early_access/panama/docs/specs/security/standard-names.html#parameterspec-names<a>
 */
public enum ECDHCurves {

	secp256r1("secp256r1"),
	secp384r1("secp384r1"),
	secp521r1("secp521r1");
	
	String curveName;

	ECDHCurves(String curveName) {
		this.curveName = curveName;
	}
	
}
