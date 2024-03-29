package io.github.awidesky.jCipherUtil.cipher.asymmetric;

import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.util.Optional;

import javax.crypto.Cipher;

import io.github.awidesky.jCipherUtil.AbstractCipherUtil;
import io.github.awidesky.jCipherUtil.cipher.asymmetric.key.AsymmetricKeyMaterial;
import io.github.awidesky.jCipherUtil.exceptions.OmittedCipherException;
import io.github.awidesky.jCipherUtil.key.KeySize;

/**
 * superclass for asymmetric {@code CipherUtil} classes.
 * <p>
 * A {@code AsymmetricCipherUtil} is for encryption/decryption with asymmetric cipher algorithm(e.g. RSA).
 * It can generate new key pair, or use existing one. It can even initialized with one of {@code PrivateKey} 
 * and {@code PublicKey} to use only in either encryption/decryption.
 * */
public abstract class AsymmetricCipherUtil extends AbstractCipherUtil {

	protected AsymmetricKeyMaterial key;

	public AsymmetricCipherUtil(AsymmetricKeyMaterial keyMet, int bufferSize) {
		super(bufferSize);
		this.key = keyMet;
	}

	/**
	 * Initialize backing {@code CipherUtil} for encrypt mode.
	 * 
	 * @throws OmittedCipherException If this {@code AsymmetricCipherUtil} does not have a {@code PublicKey}. 
	 * */
	@Override
	protected Cipher initEncrypt(byte[] metadata) throws OmittedCipherException {
		try {
			Cipher c = getCipherInstance();
			initCipherInstance(c, Cipher.ENCRYPT_MODE, Optional.ofNullable(key.getKey(getCipherProperty().KEY_ALGORITMH_NAME).getPublic()).orElseThrow(
					() -> new InvalidKeyException("This " + toString() + " instance does not have a public key!")));
			return c;
		} catch (InvalidKeyException e) {
			throw new OmittedCipherException(e);
		}
	}

	/**
	 * Initialize backing {@code CipherUtil} for decrypt mode.
	 * 
	 * @throws OmittedCipherException If this {@code AsymmetricCipherUtil} does not have a {@code PrivateKey}.
	 * */
	@Override
	protected Cipher initDecrypt(ByteBuffer metadata) throws OmittedCipherException {
		try {
			Cipher c = getCipherInstance();
			initCipherInstance(c, Cipher.DECRYPT_MODE, Optional.ofNullable(key.getKey(getCipherProperty().KEY_ALGORITMH_NAME).getPrivate()).orElseThrow(
					() -> new InvalidKeyException("This " + toString() + " instance does not have a private key!")));
			return c;
		} catch (InvalidKeyException e) {
			throw new OmittedCipherException(e);
		}
	}
	
	/**
	 * Generate a key pair of given size
	 * @param keySize size of the key
	 * @return newly generated key pair
	 */
	public abstract KeyPair generateKeyPair(KeySize keySize);
	
	/**
	 * Returns size of the public key.
	 * @return size of the public key.
	 */
	public abstract int publicKeyLength();
	/**
	 * Returns size of the private key.
	 * @return size of the private key.
	 */
	public abstract int privateKeyLength();
	
	/***
	 * Add length of public/private key of this instance to the return value of {@code AbstractCipherUtil#toString()}
	 * 
	 * @see AbstractCipherUtil#toString()
	 */
	@Override
	protected String fields() {
		return super.fields() + ", public key : " + publicKeyLength() + "bits, private key : " + privateKeyLength() + "bits";
	}
	
	@Override
	public int getMetadataLength() {
		return 0;
	}

	@Override
	public void destroyKey() {
		key.destroy();
	}
	
}
