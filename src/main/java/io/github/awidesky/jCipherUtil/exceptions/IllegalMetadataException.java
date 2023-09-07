package io.github.awidesky.jCipherUtil.exceptions;

/**
 * Thrown when provided metadata are illegal/not enough to do the cipher process.
 * For example, necessarily key is missing, iteration count is not in a valid range, etc...
 * */
public class IllegalMetadataException extends RuntimeException {

	/**
	 * Constructs a new IllegalMetadataException with the specified detail message.
	 */
	public IllegalMetadataException(String msg) {
		super(msg);
	}

	private static final long serialVersionUID = 8266879496663471496L;

}
