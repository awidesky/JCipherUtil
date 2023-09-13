package io.github.awidesky.jCipherUtil.cipher.symmetric.aes;

import java.security.SecureRandom;
import java.util.Arrays;

import io.github.awidesky.jCipherUtil.cipher.symmetric.SymmetricCipherUtilBuilder;
import io.github.awidesky.jCipherUtil.cipher.symmetric.SymmetricNonceCipherUtil;
import io.github.awidesky.jCipherUtil.cipher.symmetric.key.KeyMetadata;
import io.github.awidesky.jCipherUtil.cipher.symmetric.key.SymmetricKeyMaterial;
import io.github.awidesky.jCipherUtil.key.KeySize;
import io.github.awidesky.jCipherUtil.properties.IVCipherProperty;

/**
 * An AES/CTR/NoPadding {@code CipherUtil} with 16 byte IV.
 * */
public class AES_CTRCipherUtil extends SymmetricNonceCipherUtil {

	public final static IVCipherProperty METADATA = new IVCipherProperty("AES", "CTR", "NoPadding", "AES", 16);
	
	/**
	 * Length of the counter in bytes.
	 * the counter is 4byte long, and it will be reside in the least significant bits of the IV.
	 * 4 bytes of IV will be set to 0(zero).
	 * 4 byte of counter will handle at least 68GB of data without reusing the counter.
	 * */
	public final int counterLen;

	/**
	 * Initiate this object with given <code>counterLength</code>.
	 * The counter will be reside in the least significant bits of the IV.
	 * <code>counterLen</code> bytes of IV will be set to 0(zero).
	 * 
	 * @throws IllegalArgumentException if <code>counterLength</code> is smaller than 1 or greater than 16.
	 * */
	private AES_CTRCipherUtil(KeyMetadata keyMetadata, KeySize keySize, SymmetricKeyMaterial key, int bufferSize, int counterLength) {
		super(keyMetadata, keySize, key, bufferSize);
		if(counterLength < 1 || 16 < counterLength) throw new IllegalArgumentException("Invalid counter length : " + counterLength + ", must be 0 < c < 17");
		this.counterLen = counterLength;
	}

	/** The counter must be zero. */
	@Override
	protected byte[] generateNonce(SecureRandom sr) {
		byte[] nonce = new byte[METADATA.NONCESIZE - counterLen];
		sr.nextBytes(nonce);
		nonce = Arrays.copyOfRange(nonce, 0, 16);
		return nonce;
	}
	
	@Override
	public IVCipherProperty getCipherProperty() { return METADATA; }


	public static class Builder extends SymmetricCipherUtilBuilder<AES_CTRCipherUtil> {
		
		private int counter = 4;
		
		/**
		 * Initialize the builder with given key size.
		 * */
		public Builder(AESKeySize keySize) {
			super(keySize);
		}
		
		/**
		 * Initialize the builder with given key size and counter length.
		 * */
		public Builder(AESKeySize keySize, int counterLen) {
			super(keySize);
			counterLen(counterLen);
		}
		
		/**
		 * Configure length of the counter for CTR mode. original default value is 4.
		 * This is optional operation.
		 * */
		public AES_CTRCipherUtil.Builder counterLen(int counterLen) {
			this.counter = counterLen;
			return this;
		}
				
		/**
		 * Returns generated {@code AES_CTRCipherUtil}.
		 * */
		@Override
		public AES_CTRCipherUtil generate() { return new AES_CTRCipherUtil(keyMetadata, keySize, keyMet, bufferSize, counter); }
		
	}
}
