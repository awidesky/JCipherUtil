package io.github.awidesky.jCipher.cipher.asymmetric.rsa;

import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;

import io.github.awidesky.jCipher.cipher.asymmetric.AsymmetricCipherUtil;
import io.github.awidesky.jCipher.cipher.asymmetric.AsymmetricCipherUtilBuilder;
import io.github.awidesky.jCipher.cipher.asymmetric.key.AsymmetricKeyMaterial;
import io.github.awidesky.jCipher.properties.CipherProperty;
import io.github.awidesky.jCipher.util.exceptions.OmittedCipherException;

public class RSA_ECBCipherUtil extends AsymmetricCipherUtil {

	public final static CipherProperty METADATA = new CipherProperty("RSA", "ECB", "PKCS1Padding", "RSA");
	
	public RSA_ECBCipherUtil(CipherProperty cipherMetadata, AsymmetricKeyMaterial keyMet, int bufferSize) {
		super(METADATA, keyMet, bufferSize);
	}

	@Override
	protected CipherProperty getCipherProperty() { return METADATA; }

	@Override
	protected String fields() {
		return super.fields() + ", key size : " + getKeyLength() + "bit";
	}
	
	public int getKeyLength() {
		try {
			Cipher rsa = Cipher.getInstance(METADATA.ALGORITMH_NAME + "/" + METADATA.ALGORITMH_MODE + "/" + METADATA.ALGORITMH_PADDING);
			KeyPair kp = key.getKey(METADATA.KEY_ALGORITMH_NAME);
			if(kp == null) return -1;
			if(kp.getPublic() != null) {
				rsa.init(Cipher.ENCRYPT_MODE, kp.getPublic());
			} else {
				rsa.init(Cipher.ENCRYPT_MODE, kp.getPrivate());
			}
			return rsa.getOutputSize(0) * Byte.SIZE;
		} catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException e) {
			throw new OmittedCipherException(e);
		}
	}

	public static KeyPair generateKeyPair(RSAKeySize keySize) {
		try {
			KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(METADATA.KEY_ALGORITMH_NAME);
			keyPairGenerator.initialize(keySize.size);
			return keyPairGenerator.genKeyPair();
		} catch (NoSuchAlgorithmException e) {
			throw new OmittedCipherException(e);
		}
	}
	
	public static class Builder extends AsymmetricCipherUtilBuilder<RSA_ECBCipherUtil> {

		public Builder(KeyPair keyPair) { super(keyPair); }
		public Builder(PrivateKey key) { super(key); }
		public Builder(PublicKey key) { super(key);}

		@Override
		public RSA_ECBCipherUtil build() { return new RSA_ECBCipherUtil(METADATA, keyMet, bufferSize); }
		
	}
}
