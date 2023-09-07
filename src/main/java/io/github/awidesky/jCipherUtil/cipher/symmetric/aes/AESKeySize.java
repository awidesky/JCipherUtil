package io.github.awidesky.jCipherUtil.cipher.symmetric.aes;

import io.github.awidesky.jCipherUtil.key.KeySize;

/**
 * Denotes AES key size in bits.
 */
public class AESKeySize extends KeySize {

	public static final AESKeySize SIZE_128 = new AESKeySize(128);
	public static final AESKeySize SIZE_192 = new AESKeySize(192);
	public static final AESKeySize SIZE_256 = new AESKeySize(256);
	
	/** Create custom AES key size. */
	public AESKeySize(int size) { super(size); }
	
}
