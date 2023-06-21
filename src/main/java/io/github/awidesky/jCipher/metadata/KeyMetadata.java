package io.github.awidesky.jCipher.metadata;

public class KeyMetadata {

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
	public KeyMetadata(int saltLen, int iterationRangeStart, int iterationRangeEnd) {
		this.saltLen = saltLen;
		iterationRange[0] = iterationRangeStart;
		iterationRange[1] = iterationRangeEnd;
	}
}