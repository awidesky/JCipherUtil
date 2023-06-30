package io.github.awidesky.jCipher.cipher.symmetric.key;

import io.github.awidesky.jCipher.key.KeyMetadata;
import io.github.awidesky.jCipher.key.KeySize;

public class SymmetricKeyMetadata extends KeyMetadata {
	
	/**
	 * Standard salt length and iteration count that commonly used in 2023.
	 * https://en.wikipedia.org/wiki/PBKDF2
	 * In 2023, OWASP recommended to use 600,000 iterations for PBKDF2-HMAC-SHA256 and 210,000 for PBKDF2-HMAC-SHA512.
	 */
	public static final KeyMetadataBuilder STANDARD = new KeyMetadataBuilder(32, 210000, 400000);
	/**
	 * Standard salt length and iteration count that used default.
	 * <p>Provides better security than {@code STANDARD}
	 */
	public static final KeyMetadataBuilder DEFAULT = new KeyMetadataBuilder(64, 600000, 800000);
	
	
	/** Length of salt */
	public final int saltLen;
	/** Range of salting iteration count */
	public final int[] iterationRange = new int[2];
	
	/**
	 * @param saltLen length of the salt.
	 * @param iterationRangeStart the least salting iteration count.
	 * @param iterationRangeEnd the upper bound (exclusive) for salting iteration count.
	 * Iteration count bigger than this value will not be accepted.
	 * */
	public SymmetricKeyMetadata(KeySize keyLen, int saltLen, int iterationRangeStart, int iterationRangeEnd) {
		super(keyLen);
		this.saltLen = saltLen;
		iterationRange[0] = iterationRangeStart;
		iterationRange[1] = iterationRangeEnd;
	}
	
	public static class KeyMetadataBuilder {
		private final int saltLen;
		private final int[] iterationRange = new int[2];

		private KeyMetadataBuilder(int saltLen, int iterationRangeStart, int iterationRangeEnd) {
			this.saltLen = saltLen;
			iterationRange[0] = iterationRangeStart;
			iterationRange[1] = iterationRangeEnd;
		}
		
		public SymmetricKeyMetadata with(KeySize keyLen) { return new SymmetricKeyMetadata(keyLen, saltLen, iterationRange[0], iterationRange[1]); } 
	}
}