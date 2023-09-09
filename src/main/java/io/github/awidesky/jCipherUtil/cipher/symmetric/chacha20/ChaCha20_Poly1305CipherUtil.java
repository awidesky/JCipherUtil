package io.github.awidesky.jCipherUtil.cipher.symmetric.chacha20;

import io.github.awidesky.jCipherUtil.cipher.symmetric.SymmetricCipherUtilBuilder;
import io.github.awidesky.jCipherUtil.cipher.symmetric.key.KeyMetadata;
import io.github.awidesky.jCipherUtil.cipher.symmetric.key.SymmetricKeyMaterial;
import io.github.awidesky.jCipherUtil.key.KeySize;
import io.github.awidesky.jCipherUtil.properties.IVCipherProperty;

/**
 * A ChaCha20-Poly1305/None/NoPadding {@code CipherUtil} with 12 byte nonce.
 * */
public class ChaCha20_Poly1305CipherUtil extends AbstractChaCha20CipherUtil {

	public final static IVCipherProperty METADATA = new IVCipherProperty("ChaCha20-Poly1305", "None", "NoPadding", "ChaCha20", 12);
	
	/**
	 * Construct this {@code ChaCha20_Poly1305CipherUtil} with given parameters.
	 * */
	private ChaCha20_Poly1305CipherUtil(KeyMetadata keyMetadata, KeySize keySize, SymmetricKeyMaterial key, int bufferSize) {
		super(keyMetadata, keySize, key, bufferSize);
	}

	@Override
	public IVCipherProperty getCipherProperty() { return METADATA; }


	public static class Builder extends SymmetricCipherUtilBuilder<ChaCha20_Poly1305CipherUtil> {
		
		/**
		 * Initialize the builder with given key size.
		 * */
		public Builder(ChaCha20KeySize keySize) {
			super(keySize);
		}
		
		/**
		 * Returns generated {@code ChaCha20_Poly1305CipherUtil}.
		 * */
		@Override
		public ChaCha20_Poly1305CipherUtil generate() { return new ChaCha20_Poly1305CipherUtil(keyMetadata, keySize, keyMet, bufferSize); }
		
	}
}
