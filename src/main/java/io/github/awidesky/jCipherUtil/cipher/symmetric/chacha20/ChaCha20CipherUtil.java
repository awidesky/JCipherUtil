package io.github.awidesky.jCipherUtil.cipher.symmetric.chacha20;

import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.spec.ChaCha20ParameterSpec;

import io.github.awidesky.jCipherUtil.cipher.symmetric.SymmetricCipherUtilBuilder;
import io.github.awidesky.jCipherUtil.cipher.symmetric.key.ByteArrayKeyMaterial;
import io.github.awidesky.jCipherUtil.cipher.symmetric.key.KeyMetadata;
import io.github.awidesky.jCipherUtil.cipher.symmetric.key.PasswordKeyMaterial;
import io.github.awidesky.jCipherUtil.cipher.symmetric.key.SymmetricKeyMaterial;
import io.github.awidesky.jCipherUtil.key.KeySize;
import io.github.awidesky.jCipherUtil.properties.IVCipherProperty;

/**
 * A ChaCha20 {@code CipherUtil} with 12 byte nonce.
 * */
public class ChaCha20CipherUtil extends AbstractChaCha20CipherUtil {

	public final static IVCipherProperty METADATA = new IVCipherProperty("ChaCha20", "", "", "ChaCha20", 12);
	
	/**
	 * Construct this {@code ChaCha20CipherUtil} with given parameter.
	 * */
	private ChaCha20CipherUtil(KeyMetadata keyMetadata, KeySize keySize, SymmetricKeyMaterial key, int bufferSize) {
		super(keyMetadata, keySize, key, bufferSize);
	}
	/**
	 * Generate {@code AlgorithmParameterSpec} for this ChaCha20 cipher.
	 * Use 12byte nonce, and a counter initialized to 0.
	 * */
	@Override
	protected AlgorithmParameterSpec getAlgorithmParameterSpec(byte[] nonce) {
		return new ChaCha20ParameterSpec(nonce, 0);
	}


	@Override
	protected IVCipherProperty getCipherProperty() { return METADATA; }

	
	public static class Builder extends SymmetricCipherUtilBuilder<ChaCha20CipherUtil> {
		
		/**
		 * Specify binary private key data and ChaCha20 key size.
		 * <p>The private key data is <b>not</b> directly used as an ChaCha20 key. Instead it will salted and hashed
		 * multiple times.
		 * 
		 * @see ByteArrayKeyMaterial#ByteArrayKeyMaterial(byte[])
		 * */
		public Builder(byte[] key, ChaCha20KeySize keySize) { super(key, keySize); }
		/**
		 * Specify password and ChaCha20 key size.
		 * 
		 * @see PasswordKeyMaterial#PasswordKeyMaterial(char[])
		 * */
		public Builder(char[] password, ChaCha20KeySize keySize) { super(password, keySize); }
		
		/**
		 * Returns generated {@code ChaCha20CipherUtil}.
		 * */
		@Override
		public ChaCha20CipherUtil build() { return new ChaCha20CipherUtil(keyMetadata, keySize, keyMet, bufferSize); }
		
	}
}
