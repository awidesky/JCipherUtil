package io.github.awidesky.jCipherUtil.key.keyExchange.xdh;

/**
 * Available Elliptic curves for XDH Key exchange algorithm.
 * <a href=https://download.java.net/java/early_access/panama/docs/specs/security/standard-names.html#parameterspec-names>
 * https://download.java.net/java/early_access/panama/docs/specs/security/standard-names.html#parameterspec-names<a>
 */
public enum XDHCurves {

	X25519("X25519"),
	X448("X448");
	
	String curveName;

	XDHCurves(String curveName) {
		this.curveName = curveName;
	}
	
}
