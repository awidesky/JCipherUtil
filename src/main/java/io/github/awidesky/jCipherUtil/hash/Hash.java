package io.github.awidesky.jCipherUtil.hash;

import java.util.Base64;
import java.util.HexFormat;

import io.github.awidesky.jCipherUtil.hash.checksum.CheckSumHash;
import io.github.awidesky.jCipherUtil.hash.messageDigest.MessageDigestHash;
import io.github.awidesky.jCipherUtil.messageInterface.InPut;

/**
 * A common interface for hashing functions(including checksums) utilities.
 * Provides basic update/doFinal methods and one-call digest methods
 * ({@code Hash#toBytes(Hash, InPut)}, {@code Hash#toBase64(Hash, InPut)}, and
 * {@code Hash#toHex(Hash, InPut)}) that process hash process with given
 * {@code InPut} and {@code Hash} instance in single call.
 *
 * @since 1.2.0
 * @see CheckSumHash
 * @see MessageDigestHash
 */
public interface Hash { //TODO : make enum, parameter is algorithm name/or supplier, public getInstance(). put one-time methods in the enum

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
		return doFinalhToBytes();
	}

	/**
	 * Completes the hash computation by performing final operations,
	 * and return the result as byte array.
	 * The hash digest is reset before this method returns.
	 *
	 * @return the result of hash digest
	 */
	public byte[] doFinalhToBytes();

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
		return HexFormat.of().formatHex(doFinalhToBytes());
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
		return Base64.getEncoder().encodeToString(doFinalhToBytes());
	}

	
	/**
	 * Read the data from given {@code InPut}, process them and
	 * completes the hash computation.
	 * The result is returned as a byte array.
	 * The hash digest is reset before the hash process begins, and also before this method returns.
	 *
	 * @param input input data to hash
	 * @return the result of hash digest
	 */
	public default byte[] toBytes(InPut input) {
		reset();
		byte[] buf = new byte[8 * 1024];
		int read = 0;
		while ((read = input.getSrc(buf)) != -1) {
			update(buf, 0, read);
		}
		return doFinalhToBytes();

	}

	/**
	 * Read the data from given {@code InPut}, process them and
	 * completes the hash computation.
	 * The result is returned as {@link HexFormat hex formatted} {@code String}.
	 * The hash digest is reset before the hash process begins, and also before this method returns.
	 * 
	 * 
	 * @see HexFormat 
	 * @param input input data to hash
	 * @return the result of hash digest in hex formated string
	 */
	public default String toHex(InPut input) {
		return HexFormat.of().formatHex(toBytes(input));
	}

	/**
	 * Read the data from given {@code InPut}, process them and
	 * completes the hash computation.
	 * The result is returned as {@link Base64 Base64 formatted} {@code String}.
	 * The hash digest is reset before the hash process begins, and also before this method returns.
	 * 
	 * @see Base64 
	 * @param input input data to hash
	 * @return the result of hash digest in base64 formated string
	 */
	public default String toBase64(InPut input) {
		return Base64.getEncoder().encodeToString(toBytes(input));
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
