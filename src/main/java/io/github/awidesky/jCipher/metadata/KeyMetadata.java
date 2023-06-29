package io.github.awidesky.jCipher.metadata;

public class KeyMetadata {

	/** Size of key in bits */
	public final int keyLen;
	
	public KeyMetadata(KeySize keyLen) { this.keyLen = keyLen.getSize(); }
}
