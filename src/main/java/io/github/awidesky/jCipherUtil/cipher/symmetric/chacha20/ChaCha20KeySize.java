package io.github.awidesky.jCipherUtil.cipher.symmetric.chacha20;

import io.github.awidesky.jCipherUtil.key.KeySize;

/**
 * Denotes ChaCha20 key value in bits.
 */
public class ChaCha20KeySize extends KeySize {

	public static final ChaCha20KeySize SIZE_256 = new ChaCha20KeySize(256);
	
	/** Create custom ChaCha20 key value. */
	public ChaCha20KeySize(int size) { super(size); }
	
}
