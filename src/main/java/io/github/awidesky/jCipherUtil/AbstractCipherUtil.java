package io.github.awidesky.jCipherUtil;

import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.spec.AlgorithmParameterSpec;
import java.util.function.Predicate;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;

import io.github.awidesky.jCipherUtil.exceptions.NestedIOException;
import io.github.awidesky.jCipherUtil.exceptions.NotSupposedToThrownException;
import io.github.awidesky.jCipherUtil.exceptions.OmittedCipherException;
import io.github.awidesky.jCipherUtil.messageInterface.InPut;
import io.github.awidesky.jCipherUtil.messageInterface.OutPut;
import io.github.awidesky.jCipherUtil.util.CipherMode;
import io.github.awidesky.jCipherUtil.util.CipherTunnel;
import io.github.awidesky.jCipherUtil.util.CipherUtilInputStream;
import io.github.awidesky.jCipherUtil.util.CipherUtilOutputStream;

/**
 * An abstract subclass of {@code CipherUtil} that provides a few utility methods,
 * and basic structure that every cipher suites shares.
 */
public abstract class AbstractCipherUtil implements CipherUtil {

	/**
	 * Size of the internal buffer.
	 */
	protected final int BUFFER_SIZE;
	
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
			/**
			 * Only CipherUtil subclasses(which are guaranteed to put right metadata name) can call this method.
			 * So if above exception is thrown, there must be something wrong with the library. 
			 * */
			throw new NotSupposedToThrownException(e);
		}
	}
	/**
	 * Initiate given {@code Cipher} instance.
	 * 
	 * @throws OmittedCipherException when InvalidKeyException is thrown
	 */
	protected void initCipherInstance(Cipher c, int opmode, Key key) {
		try {
			c.init(opmode, key);
		} catch (InvalidKeyException e) {
			throw new OmittedCipherException(e);
		}
	}
	/**
	 * Initiate given {@code Cipher} instance.
	 * 
	 * @throws OmittedCipherException when InvalidKeyException is thrown
	 */
	protected void initCipherInstance(Cipher c, int opmode, Key key, AlgorithmParameterSpec params) {
		try {
			c.init(opmode, key, params);
		} catch (InvalidKeyException e) {
			throw new OmittedCipherException(e);
		} catch (InvalidAlgorithmParameterException e) {
			/**
			 * Only CipherUtil subclasses(which are guaranteed to put right metadata name) can call this method.
			 * So if above exception is thrown, there must be something wrong with the library. 
			 * */
			throw new NotSupposedToThrownException(e);
		}
	}

	/**
	 * Initialize {@code Cipher} in encrypt mode so that it can be usable(be able to call {@code Cipher#update(byte[])}, {@code Cipher#doFinal()}.
	 * 
	 * @param metadata a pre-allocated byte array. The generated metadata will be written to it.
	 * 		  Size is defined in {@code AbstractCipherUtil#getMetadataLength()}.
	 * @return initiated {@code Cipher} instance
	 * 
	 * @throws NestedIOException if {@code IOException} is thrown.
	 * */
	protected abstract Cipher initEncrypt(byte[] metadata) throws NestedIOException;

	/**
	 * Initialize {@code Cipher} in decrypt mode so that it can be usable(be able to call {@code Cipher#update(byte[])}, {@code Cipher#doFinal()}.
	 * 
	 * @param metadata a {@code ByteBuffer} that contains metadata.
	 * 		  Size is defined in {@code AbstractCipherUtil#getMetadataLength()}.
	 * @return initiated {@code Cipher} instance
	 * 
	 * @throws NestedIOException if {@code IOException} is thrown.
	 * */
	protected abstract Cipher initDecrypt(ByteBuffer metadata) throws NestedIOException;
	
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
			processCipher(cipherEngine(CipherMode.ENCRYPT_MODE), in, out, BUFFER_SIZE);
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
			processCipher(cipherEngine(CipherMode.DECRYPT_MODE), in, out, BUFFER_SIZE);
		}
	}
	

	
	/**
	 * Do Cipher Process with pre-initiated {@code CipherEngine} until every data of the input is processed.
	 * 
	 * @param cipherEngine The {@code CipherEngine} instance 
	 * @param in Plain data Provider of source for encryption/decryption
	 * @param out Data Consumer that writes encrypted/decryption data to designated destination 
	 * @throws NestedIOException if {@code IOException} is thrown. If this cipher process related with
	 * external resources(like {@code File}, caller should catch {@code NestedIOException}.  
	 * @throws OmittedCipherException if a cipher-related, omitted exceptions that won't happen unless
	 * there's a internal flaw in the cipher library.
	 * */
	private static void processCipher(CipherEngine cipherEngine, InPut in, OutPut out, int bufferSize) {
		byte[] buf = new byte[bufferSize];
		while (true) {
			int read = in.getSrc(buf);
			if(read == -1) break;
			byte[] result = cipherEngine.update(buf, 0, read);
			if (result != null) out.consumeResult(result);
		}
		out.consumeResult(cipherEngine.doFinal());
	}
	
	
	@Override
	public CipherTunnel cipherTunnel(InPut in, OutPut out, CipherMode mode) {
		return new CipherTunnel(cipherEngine(mode), in, out, BUFFER_SIZE);
	}

	@Override
	public CipherEngine cipherEngine(CipherMode mode) { // TODO : separate
		if(mode == CipherMode.ENCRYPT_MODE) {
			return new CipherEncryptEngine(this::initEncrypt, getMetadataLength());
		} else if(mode == CipherMode.DECRYPT_MODE) {
			return new CipherDecryptEngine(this::initDecrypt, getMetadataLength());
		} else {
			// This must not happen. only for barrier against to possible changes of CipherMode in the future. 
			throw new OmittedCipherException(new IllegalArgumentException("Unknown cipher mode : " + mode.name()));
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
	public abstract int getMetadataLength();

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
