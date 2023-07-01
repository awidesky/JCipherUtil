package io.github.awidesky.jCipher.key.keyExchange.ECDH;

//standard curven names https://download.java.net/java/early_access/panama/docs/specs/security/standard-names.html#parameterspec-names
public enum ECDHCurves {

	secp256r1("secp256r1"),
	secp384r1("secp384r1"),
	secp521r1("secp521r1"),
	brainpoolP256r1("brainpoolP256r1"),
	brainpoolP384r1("brainpoolP384r1"),
	brainpoolP512r1("brainpoolP512r1");
	
	String curveName;

	ECDHCurves(String curveName) {
		this.curveName = curveName;
	}
	
}
