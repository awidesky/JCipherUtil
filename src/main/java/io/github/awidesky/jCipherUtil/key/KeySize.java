package io.github.awidesky.jCipherUtil.key;

/**
 * Base class for all subclass represent key size for Cipher algorithms.
 * */
public class KeySize {

	public final int size;//TODO : Value
	
	/**
	 * Constructs the instance with given key size.
	 * */
	protected KeySize(int size) { this.size = size; }
}
