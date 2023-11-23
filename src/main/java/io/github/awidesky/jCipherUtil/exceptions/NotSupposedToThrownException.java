package io.github.awidesky.jCipherUtil.exceptions;


/**
 * NotSupposedToThrownException represents an Exception that should not be thrown in "normal situation".
 * It means when a NotSupposedToThrownException is thrown, it is caused by a bug of {@code JCipherUtil} library.
 * If the library is not flawed, and has passed the test, a NotSupposedToThrownException must never be thrown.
 * <p>
 * when you happened to encounter a NotSupposedToThrownException, please submit an 
 * <a href=https://github.com/awidesky/JCipherUtil/issues>issue</a>.
 */
public class NotSupposedToThrownException extends RuntimeException {

	private static final long serialVersionUID = 4153871170915147650L;
	private final Exception nested;
	
	/**
	 * Constructs a new NotSupposedToThrownException with given cause(nested {@code Exception})
	 */
	public NotSupposedToThrownException(Exception nested) {
		super(nested);
		this.nested = nested;
	}
	/**
	 * @return nested {@code Exception}
	 */
	public Exception getNested() {
		return nested;
	}
	/**
	 * Returns the detail message string of nested {@code Exception}.
	 * @return {@code Exception#getMessage()} of nested {@code Exception}
	 */
	@Override
	public String getMessage() {
		return nested.getMessage();
	}
	/**
	 * Returns the localized description of nested {@code Exception}.
	 * @return {@code Exception#getLocalizedMessage()} of nested {@code Exception}
	 */
	@Override
	public String getLocalizedMessage() {
		return nested.getLocalizedMessage();
	}
	/**
	 * Returns the cause of this {@code NotSupposedToThrownException}, which is the nested {@code Exception}
	 */
	@Override
	public synchronized Throwable getCause() {
		return nested;
	}
	/**
	 * Returns a short description of this {@code NotSupposedToThrownException} and the nested {@code Exception}
	 * */
	@Override
	public String toString() {
		return getClass().getSimpleName() + " with nested " + nested.toString();
	}

}
