package io.github.awidesky.jCipherUtil.cipher.asymmetric.key;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

public abstract class AsymmetricKeyMaterial {

	/**
	 * Generate {@link KeyPair}.
	 * If there's already a {@code KeyPair} previously generated, or this {@code AsymmetricKeyMaterial} is constructed with a {@code PublicKey},
	 * {@code PrivateKey} or {@code KeyPair}, return it.
	 * Else, new {@code KeyPair} will be generated.
	 * 
	 * @see AsymmetricKeyMaterial#AsymmetricKeyMaterial(PublicKey)
	 * @see AsymmetricKeyMaterial#AsymmetricKeyMaterial(PrivateKey)
	 * @see AsymmetricKeyMaterial#AsymmetricKeyMaterial(KeyPair)
	 */
	public abstract KeyPair getKey(String algorithm);
	
}
