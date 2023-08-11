package io.github.awidesky.jCipherUtil.cipher.symmetric.chacha20;

import io.github.awidesky.jCipherUtil.key.KeySize;

public class ChaCha20KeySize extends KeySize {

	public static final ChaCha20KeySize SIZE_256 = new ChaCha20KeySize(256);
	
	public ChaCha20KeySize(int size) { super(size); }
	
}
