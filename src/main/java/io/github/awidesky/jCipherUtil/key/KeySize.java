package io.github.awidesky.jCipherUtil.key;

/**
 * Base class for all subclass represent key value for Cipher algorithms.
 * */
public class KeySize {

	public final int value;
	
	/**
	 * Constructs the instance with given key size value.
	 * */
	protected KeySize(int value) { this.value = value; }
}
