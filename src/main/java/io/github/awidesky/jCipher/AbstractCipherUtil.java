package io.github.awidesky.jCipher;

import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import io.github.awidesky.jCipher.cipher.symmetric.SymmetricCipherUtil;
import io.github.awidesky.jCipher.messageInterface.MessageConsumer;
import io.github.awidesky.jCipher.messageInterface.MessageProvider;
import io.github.awidesky.jCipher.properties.CipherProperty;
import io.github.awidesky.jCipher.util.NestedIOException;
import io.github.awidesky.jCipher.util.OmittedCipherException;

public abstract class AbstractCipherUtil implements CipherUtil {

	protected Cipher cipher;
	protected final int BUFFER_SIZE;
	protected CipherProperty cipherMetadata;
	
	/**
	 * Construct this {@code AbstractCipherUtil} with given {@code CipherProperty} and default buffer size.
	 * */
	public AbstractCipherUtil(CipherProperty cipherMetadata) {
		this(cipherMetadata, 8 * 1024);
	}
	/**
	 * Construct this {@code AbstractCipherUtil} with given {@code CipherProperty} and buffer size.
	 * */
	public AbstractCipherUtil(CipherProperty cipherMetadata, int bufferSize) {
		this.cipherMetadata = cipherMetadata;
		this.BUFFER_SIZE = bufferSize;
		try {
			cipher = Cipher.getInstance(getCipherProperty().ALGORITMH_NAME + "/" + getCipherProperty().ALGORITMH_MODE + "/" + getCipherProperty().ALGORITMH_PADDING);
		} catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
			throw new OmittedCipherException(e);
		}
	}
	
	/**
	 * @return <code>CipherProperty</code> of this <code>CipherUtil</code>
	 * */
	protected abstract CipherProperty getCipherProperty();
	/**
	 * Generate new {@code Key} for encryption.
	 * */
	protected abstract Key getEncryptKey();
	/**
	 * Generate new {@code Key} for decryption.
	 * */
	protected abstract Key getDecryptKey();

	/**
	 * Initialize <code>Cipher</code> in encrypt mode so that it can be usable(be able to call <code>cipher.update</code>, <code>cipher.doFinal</code>
	 * In default, this method generates random salt and iteration count, initiate the <code>Cipher</code> instance, and write iteration count and salt
	 * to {@code MessageConsumer}.
	 * This method can be override to generate and write additional metadata(like Initial Vector)
	 * @throws NestedIOException if {@code IOException} is thrown.
	 * */
	protected void initEncrypt(MessageConsumer mc) throws NestedIOException {
		try {
			cipher.init(Cipher.ENCRYPT_MODE, getEncryptKey());
		} catch (InvalidKeyException e) {
			throw new OmittedCipherException(e);
		}
	}

	/**
	 * Initialize <code>Cipher</code> in decrypt mode so that it can be usable(be able to call <code>cipher.update</code>, <code>cipher.doFinal</code>
	 * In default, this method reads iteration count and salt from {@code MessageProvider}, and initiate the <code>Cipher</code> instance
	 * .
	 * This method can be override to read additional metadata(like Initial Vector) from {@code MessageConsumer} 
	 * @throws NestedIOException if {@code IOException} is thrown.
	 * */
	protected void initDecrypt(MessageProvider mp) throws NestedIOException {
		try {
			cipher.init(Cipher.DECRYPT_MODE, getDecryptKey());
		} catch (InvalidKeyException e) {
			throw new OmittedCipherException(e);
		}		
	}


	
	/**
	 * Encrypt from source(designated as <code>MessageProvider</code>)
	 * and writes to given destination(designated as <code>MessageConsumer</code>).
	 * <p>Default implementation calls two method {@link SymmetricCipherUtil#initEncrypt(MessageConsumer)},
	 * {@link SymmetricCipherUtil#processCipher(MessageProvider, MessageConsumer)}, and close both parameters.
	 *
	 * @see SymmetricCipherUtil#initEncrypt(MessageConsumer)
	 * @see SymmetricCipherUtil#processCipher(MessageProvider, MessageConsumer)
	 * 
	 * @param mp Plain data Provider of source for encryption
	 * @param mc Data Consumer that writes encrypted data to designated destination 
	 * @throws NestedIOException if {@code IOException} is thrown. if this cipher process related with
	 * external resources(like {@code File}, caller should catch {@code NestedIOException}.
	 * @throws OmittedCipherException if a cipher-related, omitted exceptions that won't happen unless
	 * there's a internal flaw in the cipher library occurs.
	 * */
	@Override
	public void encrypt(MessageProvider mp, MessageConsumer mc) throws NestedIOException, OmittedCipherException {
		try (mp; mc) {
			initEncrypt(mc);
			processCipher(mp, mc);
		}
	}

	/**
	 * Decrypt from source(designated as <code>MessageProvider</code>)
	 * and writes to given destination(designated as <code>MessageConsumer</code>).
	 * <p>Default implementation calls two method {@link SymmetricCipherUtil#initDecrypt(MessageProvider)},
	 * {@link SymmetricCipherUtil#processCipher(MessageProvider, MessageConsumer)}, and close both parameters.
	 *
	 * @see SymmetricCipherUtil#initEncrypt(MessageConsumer)
	 * @see SymmetricCipherUtil#processCipher(MessageProvider, MessageConsumer)
	 * 
	 * @param mp Plain data Provider of source for encryption
	 * @param mc Data Consumer that writes encrypted data to designated destination 
	 * @throws NestedIOException if {@code IOException} is thrown. if this cipher process related with
	 * external resources(like {@code File}, caller should catch {@code NestedIOException}.  
	 * @throws OmittedCipherException if a cipher-related, omitted exceptions that won't happen unless
	 * there's a internal flaw in the cipher library occurs.
	 * */
	@Override
	public void decrypt(MessageProvider mp, MessageConsumer mc) throws NestedIOException, OmittedCipherException {
		try (mp; mc) {
			initDecrypt(mp);
			processCipher(mp, mc);
		}
	}
	
	/**
	 * Do Cipher Process with pre-initiated <code>cipher</code>.
	 * 
	 * @param mp Plain data Provider of source for encryption/decryption
	 * @param mc Data Consumer that writes encrypted/decryption data to designated destination 
	 * @throws NestedIOException if {@code IOException} is thrown. if this cipher process related with
	 * external resources(like {@code File}, caller should catch {@code NestedIOException}.  
	 * @throws OmittedCipherException if a cipher-related, omitted exceptions that won't happen unless
	 * there's a internal flaw in the cipher library occurs.
	 * */
	protected void processCipher(MessageProvider mp, MessageConsumer mc) throws NestedIOException, OmittedCipherException {
		byte[] buf = new byte[BUFFER_SIZE];
		while(true) {
			int read = mp.getSrc(buf);
			if(read == -1) break;
			byte[] result = cipher.update(buf, 0, read);
			if(result != null) mc.consumeResult(result);
		}
		try {
			mc.consumeResult(cipher.doFinal());
		} catch (IllegalStateException | IllegalBlockSizeException | BadPaddingException e) {
			throw new OmittedCipherException(e);
		}
	}

	protected String fields() {
		return "\"" + cipher.getAlgorithm() + "\" from \"" + cipher.getProvider() + "\"";
	}
	
	@Override
	public String toString() {
		return getClass().getSimpleName() + " [" + fields() + "]";
	}
}
