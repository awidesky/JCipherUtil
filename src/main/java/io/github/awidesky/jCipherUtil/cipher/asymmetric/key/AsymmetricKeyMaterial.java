package io.github.awidesky.jCipherUtil.cipher.asymmetric.key;

import java.security.KeyPair;

import io.github.awidesky.jCipherUtil.properties.CipherProperty;

/**
 * Base class of asymmetric key pair.
 * */
public abstract class AsymmetricKeyMaterial {

	/**
	 * Returns a new {@link KeyPair}.
	 * 
	 * @see CipherProperty#KEY_ALGORITMH_NAME
	 */
	public abstract KeyPair getKey(String algorithm);
	
}
