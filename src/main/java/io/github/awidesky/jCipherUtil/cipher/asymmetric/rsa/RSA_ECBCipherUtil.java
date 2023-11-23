package io.github.awidesky.jCipherUtil.cipher.asymmetric.rsa;

import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;

import io.github.awidesky.jCipherUtil.cipher.asymmetric.AsymmetricCipherUtil;
import io.github.awidesky.jCipherUtil.cipher.asymmetric.AsymmetricCipherUtilBuilder;
import io.github.awidesky.jCipherUtil.cipher.asymmetric.key.AsymmetricKeyMaterial;
import io.github.awidesky.jCipherUtil.exceptions.NotSupposedToThrownException;
import io.github.awidesky.jCipherUtil.exceptions.OmittedCipherException;
import io.github.awidesky.jCipherUtil.key.KeySize;
import io.github.awidesky.jCipherUtil.properties.CipherProperty;

/**
 * A RSA/ECB/PKCS1Padding {@code CipherUtil}.
 * */
public class RSA_ECBCipherUtil extends AsymmetricCipherUtil {

	public final static CipherProperty METADATA = new CipherProperty("RSA", "ECB", "PKCS1Padding", "RSA");
	
	private RSA_ECBCipherUtil(AsymmetricKeyMaterial keyMet, int bufferSize) {
		super(keyMet, bufferSize);
	}

	@Override
	public CipherProperty getCipherProperty() { return METADATA; }

	/**
	 * Returns estimated length of current public key.
	 * 
	 * @return key length of current {@code AsymmetricKeyMaterial}, -1 if there is no public key. Value may not be precise.
	 * */
	@Override
	public int publicKeyLength() {
		try {
			Cipher rsa = Cipher.getInstance(METADATA.ALGORITMH_NAME + "/" + METADATA.ALGORITMH_MODE + "/" + METADATA.ALGORITMH_PADDING);
			KeyPair kp = key.getKey(METADATA.KEY_ALGORITMH_NAME);
			if(kp == null) return -1;
			if(kp.getPublic() != null) {
				rsa.init(Cipher.ENCRYPT_MODE, kp.getPublic());
			} else {
				return -1;
			}
			return rsa.getOutputSize(0) * Byte.SIZE;
		} catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException e) {
			throw new NotSupposedToThrownException(e);
		}
	}

	/**
	 * Returns estimated length of current private key.
	 * 
	 * @return key length of current {@code AsymmetricKeyMaterial}, -1 if there is no private key. Value may not be precise.
	 * */
	@Override
	public int privateKeyLength() {
		try {
			Cipher rsa = Cipher.getInstance(METADATA.ALGORITMH_NAME + "/" + METADATA.ALGORITMH_MODE + "/" + METADATA.ALGORITMH_PADDING);
			KeyPair kp = key.getKey(METADATA.KEY_ALGORITMH_NAME);
			if(kp == null) return -1;
			if(kp.getPrivate() != null) {
				rsa.init(Cipher.ENCRYPT_MODE, kp.getPrivate());
			} else {
				return -1;
			}
			return rsa.getOutputSize(0) * Byte.SIZE;
		} catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException e) {
			throw new OmittedCipherException(e);
		}
	}
	
	/**
	 * Returns new key pair of this RSA algorithm.
	 * 
	 * @param keySize Required value of key
	 */
	public static KeyPair generateKeyPair(RSAKeySize keySize) {
		try {
			KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(METADATA.KEY_ALGORITMH_NAME);
			keyPairGenerator.initialize(keySize.value);
			return keyPairGenerator.genKeyPair();
		} catch (NoSuchAlgorithmException e) {
			throw new OmittedCipherException(e);
		}
	}
	
	@Override
	public KeyPair generateKeyPair(KeySize keySize) {
		return generateKeyPair(new RSAKeySize(keySize.value));
	}


	public static class Builder extends AsymmetricCipherUtilBuilder<RSA_ECBCipherUtil> {

		public Builder(KeyPair keyPair) { super(keyPair); }
		/**
		 * Build {@code RSA_ECBCipherUtil} with {@code PrivateKey} only.
		 * */
		public Builder(PrivateKey key) { super(key); }
		/**
		 * Build {@code RSA_ECBCipherUtil} with {@code PublicKey} only.
		 * */
		public Builder(PublicKey key) { super(key); }

		/**
		 * Returns generated {@code RSA_ECBCipherUtil}.
		 * */
		@Override
		public RSA_ECBCipherUtil build() { return new RSA_ECBCipherUtil(keyMet, bufferSize); }
		
	}
}
