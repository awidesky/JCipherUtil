package io.github.awidesky.jCipherUtil.cipher.symmetric;

import java.nio.ByteBuffer;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.NullCipher;

import io.github.awidesky.jCipherUtil.cipher.symmetric.key.KeyMetadata;
import io.github.awidesky.jCipherUtil.exceptions.NestedIOException;
import io.github.awidesky.jCipherUtil.properties.CipherProperty;

public class NullCipherUtil extends SymmetricCipherUtil {

	private static final CipherProperty METADATA = new CipherProperty("NullCipher", "null", "null", "null");
	
	protected NullCipherUtil(int bufferSize) {
		super(null, null, null, bufferSize);
	}

	
	/**
	 * Generates random salt and iteration count, initiate the <code>Cipher</code> instance.
	 * Generated metadata will written to the parameter.
	 * This method can be override to generate and write additional metadata(like Initial Vector).
	 * 
	 * @param metadata a pre-allocated byte array. The generated metadata will be written to it.
	 * 		  Size is defined in {@code AbstractCipherUtil#getMetadataLength()}.
	 * @return initiated {@code Cipher} instance
	 * */
	@Override
	protected Cipher initEncrypt(byte[] metadata) throws NestedIOException {
		return new NullCipher();
	}

	/**
	 * Reads iteration count and salt from the given metadata, and initiate the <code>Cipher</code> instance.
	 * This method can be override to read additional metadata(like initial vector).
	 *
	 * @param metadata a {@code ByteBuffer} that contains metadata.
	 * 		  Size is defined in {@code AbstractCipherUtil#getMetadataLength()}.
	 * @return initiated {@code Cipher} instance
	 * */
	@Override
	protected Cipher initDecrypt(ByteBuffer metadata) throws NestedIOException {
		return new NullCipher();
	}
	
	@Override
	public CipherProperty getCipherProperty() {
		return METADATA;
	}

	@Override
	public int getMetadataLength() { return 0; }

	/**
	 * Generate random iteration count with given {@code SecureRandom} instance.
	 * Size of the iteration count is determined by {@code KeyMetadata}.
	 * 
	 * @return randomly decided number of iteration count
	 * */
	protected int generateIterationCount(SecureRandom sr) { return 0; }

	public KeyMetadata getKeyMetadata() { return new KeyMetadata(0, 0, 1); }
	
	/**
	 * Returns the size of the key
	 * @return the size of the key
	 */
	public int keySize() { return 0; }

	/**
	 * @return String represents this CipherUtil instance. <code>super.fields()</code> will be followed by value of the key and salt, iteration count range.
	 * */
	@Override
	protected String fields() { return "no fields"; }
	
	@Override
	public void destroyKey() {}

	public static class Builder extends SymmetricCipherUtilBuilder<NullCipherUtil> {
		
		/**
		 * Initialize the builder with given key size.
		 * */
		public Builder() {
			super(null);
		}
		
		/**
		 * Returns generated {@code AES_GCMCipherUtil}.
		 * */
		@Override
		public NullCipherUtil generate() { return new NullCipherUtil(bufferSize); }
		
	}
}
