package io.github.awidesky.jCipherUtil.util.cipherEngine;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;

import io.github.awidesky.jCipherUtil.exceptions.OmittedCipherException;
import io.github.awidesky.jCipherUtil.util.CipherMode;


/**
 * A {@code CipherEngine} is a basically a wrapper of
 * {@code javax.crypto.Cipher} that take cases of
 * metadata reading/generating, and inner buffering,
 */
public abstract class CipherEngine { //TODO : Thread safe version?

	protected Cipher c;
	protected CipherMode mode;
	protected boolean finished = false;
	
	/**
	 * Set the {@code CipherMode} for this CipherEngine.
	 * @param mode the cipher mode.
	 */
	protected CipherEngine(CipherMode mode) {
		//TODO : if inner logic of CipherUtil will use CipherEngine, add the subclasses to root package, with package-private constructor.
		this.mode = mode;
	}
	
    /**
     * Continues a multiple-part encryption or decryption operation
     * (depending on the CipherMode), processing another data part.
     *
     * <p>The bytes in the {@code input} buffer are processed, and the
     * result is stored in a new buffer.
     *
     * <p>If the cipher process is finished({@code doFinal} method is called),
     * this method returns {@code null}.
     * 
     * <p>This method calls the {@code update} method of three arguments with the arguments
     * {@code buf}, {@code 0}, and {@code buf.length}.
     *
     * @param buf the input buffer
     *
     * @return the new buffer with the result, or null if the cipher process is finished.
     */
	public byte[] update(byte[] buf) {
		return update(buf, 0, buf.length);
	}
	
	/**
	 * Continues a multiple-part encryption or decryption operation
	 * (depending on the CipherMode), processing another data part.
	 * This method reads up to {@code len} bytes of data from index {@code off}.
	 *
	 * <p>The bytes in the {@code input} buffer are processed, and the
	 * result is stored in a new buffer.
	 *
	 * <p>If the cipher process is finished({@code doFinal} method is called),
	 * this method returns {@code null}.
	 *
	 * @param buf the input buffer
	 * @param off the start offset off {@code buf}
	 * @param len the maximum number of bytes read.
	 *
	 * @return the new buffer with the result, or null if the cipher process is finished.
	 */
	public abstract byte[] update(byte[] buf, int off, int len);
	
	/**
	 * Finishes the multiple-part encryption or decryption operation
	 * (depending on the CipherMode), and mark this CipherEngine as finished.
	 * 
	 * @return the last cipher process result in a new buffer, or {@code null}
	 * if the CipherEngine is already finished before.
	 */
	public byte[] doFinal() {
		if(finished) return null;
		finished = true;
		try {
			return c.doFinal();
		} catch (IllegalBlockSizeException | BadPaddingException e) {
			throw new OmittedCipherException(e);
		}
	}
	/**
	 * After processing the given buffer(depending on the CipherMode),
	 * finishes the multiple-part encryption or decryption operation,
	 * and mark this CipherEngine as finished.
	 * 
	 * @return the last cipher process result in a new buffer, or {@code null}
	 * if the CipherEngine is already finished before.
	 */
	public byte[] doFinal(byte[] buf) {
		if(finished) return null;
		if(buf == null) return doFinal();
		
		byte[] updated = update(buf);
		byte[] doFinal = doFinal();
		byte[] ret = new byte[updated.length + doFinal.length];
		System.arraycopy(updated, 0, ret, 0, updated.length);
		System.arraycopy(doFinal, 0, ret, updated.length, doFinal.length);
		
		return ret;
	}

	/**
	 * Returns {@code true} if the cipher process is finished({@code doFinal()} method was called)
	 * @return {@code true} if the cipher process is finished({@code doFinal()} method was called), else {@code false}
	 */
	public boolean isFinished() { return finished; }
	/**
	 * Returns the cipher mode of this CipherEngine
	 * @return the cipher mode of this CipherEngine
	 */
	public CipherMode mode() { return mode; }
}


