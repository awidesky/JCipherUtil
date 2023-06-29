package io.github.awidesky.jCipher.cipher.asymmetric.key;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import javax.security.auth.DestroyFailedException;

import io.github.awidesky.jCipher.util.OmittedCipherException;

public class AsymmetricKeyMaterial {

	private final int keySize;
	private final KeyPairGenerator keyPairGenerator;
	private final KeyFactory keyFactory;
	private KeyPair keyPair = null;

	public AsymmetricKeyMaterial(String algorithm, int keySize) throws OmittedCipherException {
		try {
			this.keySize = keySize;
			this.keyPairGenerator = KeyPairGenerator.getInstance(algorithm);
			this.keyFactory = KeyFactory.getInstance(algorithm);
		} catch (NoSuchAlgorithmException e) {
			throw new OmittedCipherException(e);
		}
	}

	public AsymmetricKeyMaterial(PublicKey key) throws OmittedCipherException {
		this.keySize = -1;
		this.keyPairGenerator = null;
		this.keyFactory = null;
		this.keyPair = new KeyPair(key, null);
	}
	public AsymmetricKeyMaterial(PrivateKey key) throws OmittedCipherException {
		this.keySize = -1;
		this.keyPairGenerator = null;
		this.keyFactory = null;
		this.keyPair = new KeyPair(null, key);
	}
	public AsymmetricKeyMaterial(KeyPair keyPair) throws OmittedCipherException {
		this.keySize = -1;
		this.keyPairGenerator = null;
		this.keyFactory = null;
		this.keyPair = keyPair;
	}

	/**
	 * Generate {@link javax.crypto.KeyPair}.
	 * If there's already a {@code KeyPair} previously generated, or this {@code AsymmetricKeyMaterial} is constructed with a {@code PublicKey},
	 * {@code PrivateKey} or {@code KeyPair}, return it.
	 * Else, new {@code KeyPair} will be generated.
	 * 
	 * @see AsymmetricKeyMaterial#AsymmetricKeyMaterial(PublicKey)
	 * @see AsymmetricKeyMaterial#AsymmetricKeyMaterial(PrivateKey)
	 * @see AsymmetricKeyMaterial#AsymmetricKeyMaterial(KeyPair)
	 */
	public KeyPair getKey() {
		if(keyPair == null) {
			keyPairGenerator.initialize(keySize);
			return keyPair = keyPairGenerator.genKeyPair();
		} else {
			return keyPair;
		}
	}
	
	/**
	 * Destroy the {@code KeyPair}.
	 * */
	public void destroy() throws DestroyFailedException {
		keyPair = null;
	}
	
	
	public String getBase64EncodedKey(PublicKey publicKey) { //TODO : uses of these??
        return Base64.getEncoder().encodeToString(publicKey.getEncoded());
	}
	public String getBase64EncodedKey(PrivateKey privateKey) {
		return Base64.getEncoder().encodeToString(privateKey.getEncoded());
	}

	public KeyPair getBase64DecodedPublicKeyPair(String publicKey, String privateKey) throws OmittedCipherException {
		return new KeyPair(getBase64DecodedPublicKey(publicKey), getBase64DecodedPrivateKey(privateKey));
	}

	public PublicKey getBase64DecodedPublicKey(String publicKey) throws OmittedCipherException {
		try {
			return keyFactory.generatePublic(new X509EncodedKeySpec(Base64.getDecoder().decode(publicKey)));
		} catch (InvalidKeySpecException e) {
			throw new OmittedCipherException(e);
		}
	}
	public PrivateKey getBase64DecodedPrivateKey(String privateKey) throws OmittedCipherException {
		try {
			return keyFactory.generatePrivate(new PKCS8EncodedKeySpec(Base64.getDecoder().decode(privateKey)));
		} catch (InvalidKeySpecException e) {
			throw new OmittedCipherException(e);
		}
	}
	
}
