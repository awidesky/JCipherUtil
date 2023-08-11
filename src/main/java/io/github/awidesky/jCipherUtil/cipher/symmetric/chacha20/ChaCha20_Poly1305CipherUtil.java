package io.github.awidesky.jCipherUtil.cipher.symmetric.chacha20;

import io.github.awidesky.jCipherUtil.cipher.symmetric.SymmetricCipherUtilBuilder;
import io.github.awidesky.jCipherUtil.cipher.symmetric.key.KeyMetadata;
import io.github.awidesky.jCipherUtil.cipher.symmetric.key.SymmetricKeyMaterial;
import io.github.awidesky.jCipherUtil.key.KeySize;
import io.github.awidesky.jCipherUtil.properties.CipherProperty;
import io.github.awidesky.jCipherUtil.properties.IVCipherProperty;

public class ChaCha20_Poly1305CipherUtil extends AbstractChaCha20CipherUtil {

	public final static IVCipherProperty METADATA = new IVCipherProperty("ChaCha20-Poly1305", "None", "NoPadding", "ChaCha20", 12);
	
	/**
	 * Construct this {@code ChaCha20_Poly1305CipherUtil} with given {@code SymmetricKeyMetadata} and buffer size.
	 * */
	private ChaCha20_Poly1305CipherUtil(CipherProperty cipherMetadata, KeyMetadata keyMetadata, KeySize keySize, SymmetricKeyMaterial key, int bufferSize) {
		super(cipherMetadata, keyMetadata, keySize, key, bufferSize);
	}

	@Override
	protected IVCipherProperty getCipherProperty() { return METADATA; }


	public static class Builder extends SymmetricCipherUtilBuilder<ChaCha20_Poly1305CipherUtil> {
		
		public Builder(byte[] key, ChaCha20KeySize keySize) { super(key, keySize); }
		public Builder(char[] password, ChaCha20KeySize keySize) { super(password, keySize); }
		
		@Override
		public ChaCha20_Poly1305CipherUtil build() { return new ChaCha20_Poly1305CipherUtil(METADATA, keyMetadata, keySize, keyMet, bufferSize); }
		
	}
}
