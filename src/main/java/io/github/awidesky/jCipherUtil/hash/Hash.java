package io.github.awidesky.jCipherUtil.hash;

import java.util.Base64;
import java.util.HexFormat;

/**
 * A common interface for hashing functions(including checksums) utilities.
 * Provides basic update/doFinal methods.
 *
 * @since 1.2.0
 * @see CheckSumHash
 * @see MessageDigestHash
 */
public interface Hash {
//TODO : version name change
	/**
	 * Continues the hash computation with the given {@code buf}.
	 * <p>
	 * This method calls the {@code update} method of three arguments with the
	 * arguments {@code buf}, {@code 0}, and {@code buf.length}.
	 *
	 * @param buf partial data of hash input
	 */
	public default void update(byte[] buf) {
		update(buf, 0, buf.length);
	}

	/**
	 * Continues the hash computation with the given {@code buf}.
	 *
	 * @param buf partial data of hash input
	 * @param offset offset of the input buffer to begin the digest
	 * @param len number of bytes to digest
	 */
	public void update(byte[] buf, int offset, int len);

	/**
	 * After updating with given buffer,
	 * completes the hash computation by performing final operations,
	 * and return the result as byte array.
	 * The hash digest is reset before this method returns.
	 *
	 * @param buf last partial data of hash input
	 * @return the result of hash digest
	 */
	public default byte[] doFinalToBytes(byte[] buf) {
		update(buf);
		return doFinalToBytes();
	}

	/**
	 * Completes the hash computation by performing final operations,
	 * and return the result as byte array.
	 * The hash digest is reset before this method returns.
	 *
	 * @return the result of hash digest
	 */
	public byte[] doFinalToBytes();

	/**
	 * After updating with given buffer,
	 * completes the hash computation by performing final operations,
	 * and return the result as {@link HexFormat hex formatted} {@code String}.
	 * The hash digest is reset before this method returns.
	 *
	 * @see HexFormat 
	 * @param buf last partial data of hash input
	 * @return the result of hash digest in hex formated string
	 */
	public default String doFinalToHex(byte[] buf) {
		update(buf);
		return doFinalToHex();
	}

	/**
	 * Completes the hash computation by performing final operations,
	 * and return the result as {@link HexFormat hex formatted} {@code String}.
	 * The hash digest is reset before this method returns.
	 *
	 * @see HexFormat 
	 * @return the result of hash digest in hex formated string
	 */
	public default String doFinalToHex() {
		return HexFormat.of().formatHex(doFinalToBytes());
	}

	/**
	 * After updating with given buffer,
	 * completes the hash computation by performing final operations,
	 * and return the result as {@link Base64 Base64 formatted} {@code String}.
	 * The hash digest is reset before this method returns.
	 *
	 * @see Base64 
	 * @param buf last partial data of hash input
	 * @return the result of hash digest in base64 formated string
	 */
	public default String doFinalToBase64(byte[] buf) {
		update(buf);
		return doFinalToBase64();
	}


	/**
	 * Completes the hash computation by performing final operations,
	 * and return the result as {@link Base64 Base64 formatted} {@code String}.
	 * The hash digest is reset before this method returns.
	 *
	 * @see Base64 
	 * @return the result of hash digest in base64 formated string
	 */
	public default String doFinalToBase64() {
		return Base64.getEncoder().encodeToString(doFinalToBytes());
	}

	/**
	 * Returns the name of the hash algorithm
	 * 
	 * @return the name of the hash algorithm(e.g. "MD5", "CRC32", "SHA-256"
	 */
	public String getName();

	/**
	 * Resets the hash digest for further use.
	 */
	public void reset();
}
