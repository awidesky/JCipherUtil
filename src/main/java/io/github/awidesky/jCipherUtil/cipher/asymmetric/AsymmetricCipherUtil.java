package io.github.awidesky.jCipherUtil.cipher.asymmetric;

import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.util.Optional;

import javax.crypto.Cipher;

import io.github.awidesky.jCipherUtil.AbstractCipherUtil;
import io.github.awidesky.jCipherUtil.cipher.asymmetric.key.AsymmetricKeyMaterial;
import io.github.awidesky.jCipherUtil.exceptions.IllegalMetadataException;
import io.github.awidesky.jCipherUtil.exceptions.NestedIOException;
import io.github.awidesky.jCipherUtil.exceptions.OmittedCipherException;
import io.github.awidesky.jCipherUtil.key.KeySize;
import io.github.awidesky.jCipherUtil.messageInterface.InPut;
import io.github.awidesky.jCipherUtil.messageInterface.OutPut;

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
	 * @throws IllegalMetadataException If this {@code AsymmetricCipherUtil} does not have a {@code PublicKey}. 
	 * */
	@Override
	protected Cipher initEncrypt(OutPut out) throws NestedIOException {
		try {
			Cipher c = getCipherInstance();
			c.init(Cipher.ENCRYPT_MODE, Optional.ofNullable(key.getKey(getCipherProperty().KEY_ALGORITMH_NAME).getPublic()).orElseThrow(
					() -> new IllegalMetadataException("This " + toString() + " instance does not have a public key!")));
			return c;
		} catch (InvalidKeyException e) {
			throw new OmittedCipherException(e);
		}
	}

	/**
	 * Initialize backing {@code CipherUtil} for decrypt mode.
	 * 
	 * @throws IllegalMetadataException If this {@code AsymmetricCipherUtil} does not have a {@code PrivateKey}. 
	 * */
	@Override
	protected Cipher initDecrypt(InPut in) throws NestedIOException {
		try {
			Cipher c = getCipherInstance();
			c.init(Cipher.DECRYPT_MODE, Optional.ofNullable(key.getKey(getCipherProperty().KEY_ALGORITMH_NAME).getPrivate()).orElseThrow(
					() -> new IllegalMetadataException("This " + toString() + " instance does not have a private key!")));
			return c;
		} catch (InvalidKeyException e) {
			throw new OmittedCipherException(e);
		}
	}
	

	protected Cipher initEncrypt(byte[] metadata) throws NestedIOException {
		try {
			Cipher c = getCipherInstance();
			c.init(Cipher.ENCRYPT_MODE, Optional.ofNullable(key.getKey(getCipherProperty().KEY_ALGORITMH_NAME).getPublic()).orElseThrow(
					() -> new IllegalMetadataException("This " + toString() + " instance does not have a public key!")));
			return c;
		} catch (InvalidKeyException e) {
			throw new OmittedCipherException(e);
		}
	}

	protected Cipher initDecrypt(ByteBuffer metadata) throws NestedIOException {
		try {
			Cipher c = getCipherInstance();
			c.init(Cipher.DECRYPT_MODE, Optional.ofNullable(key.getKey(getCipherProperty().KEY_ALGORITMH_NAME).getPrivate()).orElseThrow(
					() -> new IllegalMetadataException("This " + toString() + " instance does not have a private key!")));
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
	protected int getMetadataLength() {
		return 0;
	}

	@Override
	public void destroyKey() {
		key.destroy();
	}
	
}
