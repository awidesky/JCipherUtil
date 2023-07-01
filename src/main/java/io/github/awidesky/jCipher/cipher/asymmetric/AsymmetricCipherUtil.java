package io.github.awidesky.jCipher.cipher.asymmetric;

import java.security.Key;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

import javax.security.auth.DestroyFailedException;

import io.github.awidesky.jCipher.AbstractCipherUtil;
import io.github.awidesky.jCipher.cipher.asymmetric.key.AsymmetricKeyMaterial;
import io.github.awidesky.jCipher.key.KeyMetadata;
import io.github.awidesky.jCipher.properties.CipherProperty;
import io.github.awidesky.jCipher.util.OmittedCipherException;

public abstract class AsymmetricCipherUtil extends AbstractCipherUtil {

	protected AsymmetricKeyMaterial key;
	protected KeyMetadata keyMetadata;
	
	public AsymmetricCipherUtil(CipherProperty cipherMetadata, KeyMetadata keyMetadata) {
		super(cipherMetadata);
		this.keyMetadata = keyMetadata;
	}

	public AsymmetricCipherUtil(CipherProperty cipherMetadata, KeyMetadata keyMetadata, int bufferSize) {
		super(cipherMetadata, bufferSize);
		this.keyMetadata = keyMetadata;
	}

	/**
	 * Initialize this {@code AsymmetricCipherUtil} with new key.
	 * */
	public AsymmetricCipherUtil init() {
		try {
			if(this.key != null) this.key.destroy();
		} catch (DestroyFailedException e) { throw new OmittedCipherException(e); }
		this.key = new AsymmetricKeyMaterial(getCipherProperty().KEY_ALGORITMH_NAME,  keyMetadata.keyLen);
		return this;
	}
	/**
	 * Initialize this {@code AsymmetricCipherUtil} with given {@code PublicKey}.
	 * */
	public AsymmetricCipherUtil init(PublicKey key) {
		try {
			if(this.key != null) this.key.destroy();
		} catch (DestroyFailedException e) { throw new OmittedCipherException(e); }
		this.key = new AsymmetricKeyMaterial(key);
		return this;
	}
	/**
	 * Initialize this {@code AsymmetricCipherUtil} with given {@code PrivateKey}.
	 * */
	public AsymmetricCipherUtil init(PrivateKey key) {
		try {
			if(this.key != null) this.key.destroy();
		} catch (DestroyFailedException e) { throw new OmittedCipherException(e); }
		this.key = new AsymmetricKeyMaterial(key);
		return this;
	}
	/**
	 * Initialize this {@code AsymmetricCipherUtil} with given {@code KeyPair}.
	 * */
	public AsymmetricCipherUtil init(KeyPair keyPair) {
		try {
			if(this.key != null) this.key.destroy();
		} catch (DestroyFailedException e) { throw new OmittedCipherException(e); }
		this.key = new AsymmetricKeyMaterial(keyPair);
		return this;
	}

	/***/
	@Override
	protected Key getEncryptKey() { return key.getKey().getPublic(); }
	@Override
	protected Key getDecryptKey() { return key.getKey().getPrivate(); }

	public KeyPair keyPair() { return key.getKey(); }
	
	@Override
	protected String fields() {
		return super.fields() + ", key size : " + keyMetadata.keyLen + "bit";
	}
	
}
