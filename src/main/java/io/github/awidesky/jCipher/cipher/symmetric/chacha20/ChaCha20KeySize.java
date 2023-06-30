package io.github.awidesky.jCipher.cipher.symmetric.chacha20;

import io.github.awidesky.jCipher.key.KeySize;

public class ChaCha20KeySize extends KeySize {

	public static final ChaCha20KeySize SIZE_256 = new ChaCha20KeySize(256);
	
	public ChaCha20KeySize(int size) { super(size); }
	
}
