package io.github.awidesky.jCipherUtil.hash.checksum;

import java.nio.ByteBuffer;
import java.util.zip.Checksum;

import io.github.awidesky.jCipherUtil.hash.Hash;
import io.github.awidesky.jCipherUtil.messageInterface.InPut;

/**
 * Subset of {@code Hash} instances that use checksum algorithms as internal hash process.
 * (e.g. Adler-32, CRC-32, CRC-32C)
 */
public abstract class CheckSumHash implements Hash {

	private Checksum checksum;
	
	/**
	 * Each {@code Checksum} instance is given from the subclass.
	 * @param checksum
	 */
	protected CheckSumHash(Checksum checksum) {
		this.checksum = checksum;
	}
	
	@Override
	public void update(byte[] buf, int offset, int len) {
		checksum.update(buf, offset, len);
	}


	@Override
	public byte[] doFinalhToBytes() {
		return ByteBuffer.allocate(Long.BYTES).putLong(finishToLong()).array();
	}

	/**
	 * Completes the hash computation by performing final operations,
	 * and return the checksum value as {@code long}.
	 * The hash digest is reset before this method returns.
	 *
	 * @return the result checksum value
	 */
	public long finishToLong() {
		long l = checksum.getValue();
		reset();
		return l;
	}
	/**
	 * After updating with given buffer,
	 * completes the hash computation by performing final operations,
	 * and return the checksum value as {@code long}.
	 * The hash digest is reset before this method returns.
	 *
	 * @param buf last partial data of hash input
	 * @return the result checksum value
	 */
	public long finishToLong(byte[] buf)  {
		checksum.update(buf);
		return finishToLong();
	}
	
	/**
	 * Read the data from given {@code InPut}, process them and
	 * completes the hash computation.
	 * The result is checksum value as {@code long}.
	 * The hash digest is reset before the hash process begins, and also before this method returns.
	 *
	 * @param input input data to hash
	 * @return the result checksum value
	 */
	public long toLong(InPut input) {
		reset();
		byte[] buf = new byte[8 * 1024];
		int read = 0;
		while((read = input.getSrc(buf)) != -1) {
			update(buf, 0, read);
		}
		return finishToLong();
	}

	@Override
	public void reset() { checksum.reset(); }
}
