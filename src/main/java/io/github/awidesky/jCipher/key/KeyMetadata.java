package io.github.awidesky.jCipher.key;

public class KeyMetadata { //TODO : delete

	/** Size of key in bits */
	public final int keyLen;
	
	public KeyMetadata(KeySize keyLen) { this.keyLen = keyLen.size; }
}
