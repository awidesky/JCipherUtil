package io.github.awidesky.jCipherUtil.cipher.symmetric.chacha20;

import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.spec.ChaCha20ParameterSpec;

import io.github.awidesky.jCipherUtil.cipher.symmetric.SymmetricCipherUtilBuilder;
import io.github.awidesky.jCipherUtil.cipher.symmetric.key.KeyMetadata;
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
	public IVCipherProperty getCipherProperty() { return METADATA; }

	
	public static class Builder extends SymmetricCipherUtilBuilder<ChaCha20CipherUtil> {

		/**
		 * Initialize the builder with given key size.
		 * */
		public Builder(ChaCha20KeySize keySize) {
			super(keySize);
		}
		
		/**
		 * Returns generated {@code ChaCha20CipherUtil}.
		 * */
		@Override
		public ChaCha20CipherUtil generate() { return new ChaCha20CipherUtil(keyMetadata, keySize, keyMet, bufferSize); }
		
	}
}
