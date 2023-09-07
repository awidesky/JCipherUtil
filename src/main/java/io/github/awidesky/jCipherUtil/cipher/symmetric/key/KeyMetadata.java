package io.github.awidesky.jCipherUtil.cipher.symmetric.key;

/**
 * Contains salt and iteration count for key generation.
 * {@code KeyMetadata} instance can be generated vi constructor with custom parameters,
 * but it is available to use pre-generated {@code KeyMetadata#STANDARD} and {@code KeyMetadata#DEFAULT}.
 * {@code STANDARD} is told to be safe enough by OWASP in current time
 * {@link https://en.wikipedia.org/wiki/PBKDF2}, but {@code CipherUtil} will use {@code DEFAULT}-which is more secure-
 * in default for security margin.
 * <p>
 * The iteration count is not represented as a single scalar, but as a <i>range</i>. And it must be specified in decryption mode too.
 * (in decryption mode, actual value of iteration count is already written in the input).
 * The reason of these is to prevent iteration count from being abnormal value. Too small value can lead to insecurity, and too large value can
 * lead to massive overhead. If iteration count value stored in the input is ill-formed
 * (possibly corrupted data or wrong metadata interpretation when decrypting, or inappropriate value is used due to user's mistake.
 * To prevent this is why implementation of {@code CipherUtil#initEncrypt} writes iteration count at the very first of the output,
 * making sure the canonical/absolute location of iteration count is always solid no matter the size of other metadata like salt and IV),
 * the cipher process may fail(the value is negative) at best.
 * <p>
 * On the other hand, it can cause vulnerability(the value is too small), or even hang like forever(the value is way to large).
 * The last one is quite likely to happen, since max value of integer is way larger then normal values of iteration count.
 * In that situation, the machine will spend a lifetime in processing key generation process. Even though the application seems to stuck,
 * there will be no diagnose or error since it's a abnormal overhead of valid logic, rather than a failure or well-known(sometimes diagnosable)
 * unresponsive behavior like thread deadlock.
 * <p>
 * By saving the iteration count as a range, user can explicitly restrict minimum/maximum value of iteration count to prevent insecurity/overhead,
 * and in encryption mode, iteration count will chose randomly between the range, providing better randomness for key derivation.
 * */
public class KeyMetadata {
	
	/**
	 * Standard salt length(32 byte) and iteration count that commonly used in 2023.
	 * In 2023, OWASP recommended to use 600,000 iterations for PBKDF2-HMAC-SHA256 and 210,000 for PBKDF2-HMAC-SHA512.
	 * <p><a href=https://en.wikipedia.org/wiki/PBKDF2>https://en.wikipedia.org/wiki/PBKDF2</a>
	 */
	public static final KeyMetadata STANDARD = new KeyMetadata(32, 210000, 400000);
	/**
	 * Standard salt length and iteration count that used default in {@code CipherUtil}.
	 * Uses 64 byte length salt and iteration coin in range of 600,000~800,000, providing better security than {@code STANDARD}
	 */
	public static final KeyMetadata DEFAULT = new KeyMetadata(64, 600000, 800000);
	
	
	/** Length of salt */
	public final int saltLen;
	/** Range of salting iteration count */
	public final int[] iterationRange = new int[2]; //TODO : 바꿀 수도 있으니까 배열 말고 두 변수로 나누
	
	/**
	 * @param saltLen length of the salt.
	 * @param iterationRangeStart the least salting iteration count.
	 * @param iterationRangeEnd the upper bound (exclusive) for salting iteration count.
	 * Iteration count bigger than this value will not be accepted.
	 * */
	public KeyMetadata(int saltLen, int iterationRangeStart, int iterationRangeEnd) {
		this.saltLen = saltLen;
		iterationRange[0] = iterationRangeStart;
		iterationRange[1] = iterationRangeEnd;
	}
	
}