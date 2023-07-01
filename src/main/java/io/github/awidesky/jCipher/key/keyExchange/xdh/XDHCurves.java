package io.github.awidesky.jCipher.key.keyExchange.xdh;

//standard curven names https://download.java.net/java/early_access/panama/docs/specs/security/standard-names.html#parameterspec-names
public enum XDHCurves {

	X25519("X25519"),
	X448("X448");
	
	String curveName;

	XDHCurves(String curveName) {
		this.curveName = curveName;
	}
	
}
