package io.github.awidesky.jCipherUtil.hash;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import io.github.awidesky.jCipherUtil.exceptions.OmittedCipherException;

/**
 * Subset of {@code Hash} instances that use {@code MessageDigest} as internal hash process.
 * <p>
 * <a href="https://docs.oracle.com/en/java/javase/11/docs/specs/security/standard-names.html#messagedigest-algorithms">
 * https://docs.oracle.com/en/java/javase/11/docs/specs/security/standard-names.html#messagedigest-algorithms</a>
 */
public class MessageDigestHash implements Hash {
	
	private final MessageDigest md;
	private final String name;

	/**
	 * Generate actual {@code MessageDigest} instance with given algorithm name.
	 * @param name name of the {@code MessageDigest} algorithm
	 */
	protected MessageDigestHash(String name) {
		try {
			this.md = MessageDigest.getInstance(name);
			this.name = name;
		} catch (NoSuchAlgorithmException e) {
			throw new OmittedCipherException(e);
		}
	}
	
	@Override
	public void update(byte[] buf, int offset, int len) {
		md.update(buf, offset, len);
	}

	@Override
	public byte[] doFinalToBytes() {
		byte[] ret = md.digest();
		reset();
		return ret;
	}

	@Override
	public String getName() { return name; }
	@Override
	public void reset() { md.reset(); }
}
