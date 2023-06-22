package io.github.awidesky.jCipher.aes;

import io.github.awidesky.jCipher.metadata.KeySize;

public class AESKeySize extends KeySize {

	public static final AESKeySize SIZE_128 = new AESKeySize(128);
	public static final AESKeySize SIZE_192 = new AESKeySize(192);
	public static final AESKeySize SIZE_256 = new AESKeySize(256);
	
	public AESKeySize(int size) { super(size); }
	
}
