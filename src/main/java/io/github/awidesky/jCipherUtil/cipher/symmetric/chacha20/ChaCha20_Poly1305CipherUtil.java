package io.github.awidesky.jCipherUtil.cipher.symmetric.chacha20;

import io.github.awidesky.jCipherUtil.cipher.symmetric.SymmetricCipherUtilBuilder;
import io.github.awidesky.jCipherUtil.cipher.symmetric.key.ByteArrayKeyMaterial;
import io.github.awidesky.jCipherUtil.cipher.symmetric.key.KeyMetadata;
import io.github.awidesky.jCipherUtil.cipher.symmetric.key.PasswordKeyMaterial;
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
	protected IVCipherProperty getCipherProperty() { return METADATA; }


	public static class Builder extends SymmetricCipherUtilBuilder<ChaCha20_Poly1305CipherUtil> {
		
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
		 * Returns generated {@code ChaCha20_Poly1305CipherUtil}.
		 * */
		@Override
		public ChaCha20_Poly1305CipherUtil build() { return new ChaCha20_Poly1305CipherUtil(keyMetadata, keySize, keyMet, bufferSize); }
		
	}
}
