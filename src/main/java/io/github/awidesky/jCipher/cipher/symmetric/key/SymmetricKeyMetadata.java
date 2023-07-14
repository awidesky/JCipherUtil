package io.github.awidesky.jCipher.cipher.symmetric.key;

public class SymmetricKeyMetadata {
	
	/**
	 * Standard salt length and iteration count that commonly used in 2023.
	 * https://en.wikipedia.org/wiki/PBKDF2
	 * In 2023, OWASP recommended to use 600,000 iterations for PBKDF2-HMAC-SHA256 and 210,000 for PBKDF2-HMAC-SHA512.
	 */
	public static final SymmetricKeyMetadata STANDARD = new SymmetricKeyMetadata(32, 210000, 400000);
	/**
	 * Standard salt length and iteration count that used default.
	 * <p>Provides better security than {@code STANDARD}
	 */
	public static final SymmetricKeyMetadata DEFAULT = new SymmetricKeyMetadata(64, 600000, 800000);
	
	
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
	public SymmetricKeyMetadata(int saltLen, int iterationRangeStart, int iterationRangeEnd) {
		this.saltLen = saltLen;
		iterationRange[0] = iterationRangeStart;
		iterationRange[1] = iterationRangeEnd;
	}
	
}