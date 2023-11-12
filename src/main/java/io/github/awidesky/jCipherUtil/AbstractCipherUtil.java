package io.github.awidesky.jCipherUtil;

import java.io.InputStream;
import java.io.OutputStream;
import java.security.NoSuchAlgorithmException;
import java.util.function.Predicate;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import io.github.awidesky.jCipherUtil.exceptions.NestedIOException;
import io.github.awidesky.jCipherUtil.exceptions.OmittedCipherException;
import io.github.awidesky.jCipherUtil.messageInterface.InPut;
import io.github.awidesky.jCipherUtil.messageInterface.OutPut;
import io.github.awidesky.jCipherUtil.properties.CipherProperty;
import io.github.awidesky.jCipherUtil.util.CipherMode;
import io.github.awidesky.jCipherUtil.util.CipherTunnel;
import io.github.awidesky.jCipherUtil.util.CipherUtilInputStream;
import io.github.awidesky.jCipherUtil.util.CipherUtilOutputStream;
import io.github.awidesky.jCipherUtil.util.cipherEngine.CipherDecryptEngine;
import io.github.awidesky.jCipherUtil.util.cipherEngine.CipherEncryptEngine;
import io.github.awidesky.jCipherUtil.util.cipherEngine.CipherEngine;

/**
 * An abstract subclass of {@code CipherUtil} that provides a few utility methods,
 * and basic structure that every cipher suites shares.
 */
public abstract class AbstractCipherUtil implements CipherUtil {

	/**
	 * Size of the internal buffer.
	 */
	protected final int BUFFER_SIZE;
	
	public boolean engine = true; //TODO : for test
	
	/**
	 * Initialize buffer value.
	 * */
	protected AbstractCipherUtil(int bufferSize) {
		this.BUFFER_SIZE = bufferSize;
	}
	
	/**
	 * Generate new {@code Cipher} instance with the subclass's cipher property.
	 * {@code Cipher#init} method must be called before using the returned {@code Cipher} instance.
	 * 
 	 * @return a newly generated {@code Cipher} instance.
	 */
	protected Cipher getCipherInstance() {
		try {
			return Cipher.getInstance(Stream.of(getCipherProperty().ALGORITMH_NAME, getCipherProperty().ALGORITMH_MODE, getCipherProperty().ALGORITMH_PADDING)
					.filter(Predicate.not(""::equals)).collect(Collectors.joining("/")));
		} catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
			throw new OmittedCipherException(e);
		}
	}
	/**
	 * @return {@code CipherProperty} object of the subclass.
	 * */
	public abstract CipherProperty getCipherProperty();

	/**
	 * Initialize {@code Cipher} in encrypt mode so that it can be usable(be able to call {@code Cipher#update(byte[])}, {@code Cipher#doFinal()}.
	 * 
	 * @throws NestedIOException if {@code IOException} is thrown.
	 * */
	protected abstract Cipher initEncrypt(OutPut out) throws NestedIOException;
	protected abstract Cipher initEncrypt(byte[] metadata) throws NestedIOException;

	/**
	 * Initialize {@code Cipher} in decrypt mode so that it can be usable(be able to call {@code Cipher#update(byte[])}, {@code Cipher#doFinal()}.
	 * 
	 * @throws NestedIOException if {@code IOException} is thrown.
	 * */
	protected abstract Cipher initDecrypt(InPut in) throws NestedIOException;
	protected abstract Cipher initDecrypt(byte[] metadata) throws NestedIOException;
	
	/**
	 * Encrypt from source(designated as <code>InPut</code>)
	 * and writes to given destination(designated as <code>OutPut</code>).
	 * Both parameters is closed when encryption is done.
	 * 
	 * @param in Plain data Provider of source for encryption
	 * @param out Data Consumer that writes encrypted data to designated destination 
	 * @throws NestedIOException if {@code IOException} is thrown. if this cipher process related with
	 * external resources(like {@code File}, caller should catch {@code NestedIOException}.
	 * @throws OmittedCipherException if a cipher-related, omitted exceptions that won't happen unless
	 * there's a internal flaw in the cipher library occurs.
	 * */
	@Override
	public void encrypt(InPut in, OutPut out) throws NestedIOException, OmittedCipherException {
		try (in; out) {
			if(engine) {
				processEngine(cipherEngine(CipherMode.ENCRYPT_MODE), in, out, BUFFER_SIZE);
			} else {
				processCipher(initEncrypt(out), in, out, BUFFER_SIZE);
			}
		}
	}

	/**
	 * Decrypt from source(designated as <code>InPut</code>)
	 * and writes to given destination(designated as <code>OutPut</code>).
	 * Both parameters is closed when decryption is done.
	 * 
	 * @param in Plain data Provider of source for encryption
	 * @param out Data Consumer that writes encrypted data to designated destination 
	 * @throws NestedIOException if {@code IOException} is thrown. if this cipher process related with
	 * external resources(like {@code File}, caller should catch {@code NestedIOException}.  
	 * @throws OmittedCipherException if a cipher-related, omitted exceptions that won't happen unless
	 * there's a internal flaw in the cipher library occurs.
	 * */
	@Override
	public void decrypt(InPut in, OutPut out) throws NestedIOException, OmittedCipherException {
		try (in; out) {
			if(engine) {
				processEngine(cipherEngine(CipherMode.DECRYPT_MODE), in, out, BUFFER_SIZE);
			} else {
				processCipher(initDecrypt(in), in, out, BUFFER_SIZE);
			}
		}
	}
	

	private static void processEngine(CipherEngine cipherEngine, InPut in, OutPut out, int bufferSize) {
		byte[] buf = new byte[bufferSize];
		while (true) {
			int read = in.getSrc(buf);
			if(read == -1) break;
			byte[] result = cipherEngine.update(buf, 0, read);
			if (result != null) out.consumeResult(result);
		}
		out.consumeResult(cipherEngine.doFinal());
	}

	/**
	 * Do Cipher Process with pre-initiated <code>cipher</code> until every data of the input is processed.
	 * 
	 * @param c The {@code Cipher} instance 
	 * @param in Plain data Provider of source for encryption/decryption
	 * @param out Data Consumer that writes encrypted/decryption data to designated destination 
	 * @throws NestedIOException if {@code IOException} is thrown. If this cipher process related with
	 * external resources(like {@code File}, caller should catch {@code NestedIOException}.  
	 * @throws OmittedCipherException if a cipher-related, omitted exceptions that won't happen unless
	 * there's a internal flaw in the cipher library.
	 * */
	private static void processCipher(Cipher c, InPut in, OutPut out, int bufferSize) throws NestedIOException, OmittedCipherException {
		byte[] buf = new byte[bufferSize];
		while(updateCipher(c, buf, in, out) != -1) { }
		doFinalCipher(c, out);
	}
	/**
	 * Tries to read from input to the buffer, process it, and write the result to output.
	 * 
	 * @return amount of data read and processed. Size of the output may be different.
	 */
	private static int updateCipher(Cipher c, byte[] buf, InPut in, OutPut out) {
		//TODO : use CipherEngine then Cipher? performance comparison needed
		try {
			int read = in.getSrc(buf);
			if(read == -1) return -1;
			byte[] result = c.update(buf, 0, read);
			if(result != null) out.consumeResult(result);
			return read;
		} catch (IllegalStateException e) {
			throw new OmittedCipherException(e);
		}
	}
	/**
	 * Does not read any more data from the input. Instead, finalize the cipher process and write
	 * all internally buffered(in {@code javax.crypto.Cipher} result data to the output.
	 *  
	 * @return amount of data processed and written.
	 */
	private static int doFinalCipher(Cipher c, OutPut out) {
		try {
			byte[] res = c.doFinal();
			out.consumeResult(res);
			return res.length;
		} catch (IllegalStateException | IllegalBlockSizeException | BadPaddingException e) {
			throw new OmittedCipherException(e);
		}
	}

	
	
	@Override
	public CipherTunnel cipherTunnel(InPut in, OutPut out, CipherMode mode) {
		return new CipherTunnel((mode == CipherMode.ENCRYPT_MODE) ? initEncrypt(out) : initDecrypt(in), in, out, BUFFER_SIZE) {
			@Override
			protected int update(Cipher cipher, byte[] buffer, InPut msgp, OutPut msgc) {
				return updateCipher(cipher, buffer, msgp, msgc);
			}
			@Override
			protected int doFinal(Cipher cipher, OutPut msgc) {
				return doFinalCipher(cipher, out);
			}
		};
	}

	@Override
	public CipherEngine cipherEngine(CipherMode mode) {
		if(mode == CipherMode.ENCRYPT_MODE) {
			return new CipherEncryptEngine(mode, this::initEncrypt, getMetadataLength());
		} else {
			return new CipherDecryptEngine(mode, this::initDecrypt, getMetadataLength());
		}
	}

	@Override
	public CipherUtilOutputStream outputStream(OutputStream out, CipherMode mode) {
		return new CipherUtilOutputStream(out, cipherEngine(mode));
	}

	@Override
	public CipherUtilInputStream inputStream(InputStream in, CipherMode mode) {
		return new CipherUtilInputStream(in, cipherEngine(mode));
	}

	/**
	 * Returns the total length of the all metadata(iteration count, salt, nonce, etc.).<br>
	 * This method is used in {@code AbstractCipherUtil#cipherEngine(io.github.awidesky.jCipherUtil.CipherMode)}
	 * @return
	 */
	protected abstract int getMetadataLength();

	/**
	 * Get algorithm name, transformation property and provider of this {@code CipherUtil}.
	 * */
	protected String fields() {
		Cipher c = getCipherInstance();
		return "\"" + c.getAlgorithm() + "\" from \"" + c.getProvider() + "\"";
	}
	
	/**
	 * Returns a String representing this {@code CipherUtil}.
	 * This includes simple name of the class, and cipher properties.
	 * 
	 * @return a String representing this {@code CipherUtil}.
	 */
	@Override
	public String toString() {
		return getClass().getSimpleName() + " [" + fields() + "]";
	}
}
