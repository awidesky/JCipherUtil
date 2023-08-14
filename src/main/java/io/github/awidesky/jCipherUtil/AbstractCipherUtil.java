package io.github.awidesky.jCipherUtil;

import java.security.NoSuchAlgorithmException;
import java.util.function.Predicate;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import io.github.awidesky.jCipherUtil.cipher.symmetric.SymmetricCipherUtil;
import io.github.awidesky.jCipherUtil.messageInterface.OutPut;
import io.github.awidesky.jCipherUtil.messageInterface.InPut;
import io.github.awidesky.jCipherUtil.properties.CipherProperty;
import io.github.awidesky.jCipherUtil.util.CipherTunnel;
import io.github.awidesky.jCipherUtil.util.UpdatableDecrypter;
import io.github.awidesky.jCipherUtil.util.UpdatableEncrypter;
import io.github.awidesky.jCipherUtil.util.exceptions.NestedIOException;
import io.github.awidesky.jCipherUtil.util.exceptions.OmittedCipherException;

public abstract class AbstractCipherUtil implements CipherUtil {

	protected final int BUFFER_SIZE;
	protected final CipherProperty cipherMetadata;
	
	/**
	 * Construct this {@code AbstractCipherUtil} with given {@code CipherProperty} and buffer size.
	 *  Subclasses should call this constructor with appropriate {@code CipherProperty} object(mostly static final field).
	 * */
	protected AbstractCipherUtil(CipherProperty cipherMetadata, int bufferSize) {
		this.cipherMetadata = cipherMetadata;
		this.BUFFER_SIZE = bufferSize;
	}
	
	protected Cipher getCipherInstance() {
		try {
			return Cipher.getInstance(Stream.of(getCipherProperty().ALGORITMH_NAME, getCipherProperty().ALGORITMH_MODE, getCipherProperty().ALGORITMH_PADDING)
					.filter(Predicate.not(""::equals)).collect(Collectors.joining("/")));
		} catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
			throw new OmittedCipherException(e);
		}
	}
	/**
	 * @return <code>CipherProperty</code> of this <code>CipherUtil</code>
	 * */
	protected abstract CipherProperty getCipherProperty();

	/**
	 * Initialize <code>Cipher</code> in encrypt mode so that it can be usable(be able to call <code>cipher.update</code>, <code>cipher.doFinal</code>
	 * In default, this method generates random salt and iteration count, initiate the <code>Cipher</code> instance, and write iteration count and salt
	 * to {@code OutPut}.
	 * This method can be override to generate and write additional metadata(like Initial Vector)
	 * @throws NestedIOException if {@code IOException} is thrown.
	 * */
	protected abstract Cipher initEncrypt(OutPut mc) throws NestedIOException;

	/**
	 * Initialize <code>Cipher</code> in decrypt mode so that it can be usable(be able to call <code>cipher.update</code>, <code>cipher.doFinal</code>
	 * In default, this method reads iteration count and salt from {@code InPut}, and initiate the <code>Cipher</code> instance
	 * .
	 * This method can be override to read additional metadata(like Initial Vector) from {@code OutPut} 
	 * @throws NestedIOException if {@code IOException} is thrown.
	 * */
	protected abstract Cipher initDecrypt(InPut mp) throws NestedIOException;


	
	/**
	 * Encrypt from source(designated as <code>InPut</code>)
	 * and writes to given destination(designated as <code>OutPut</code>).
	 * <p>Default implementation calls two method {@link SymmetricCipherUtil#initEncrypt(OutPut)},
	 * {@link SymmetricCipherUtil#processCipher(Cipher, InPut, OutPut)}, and close both parameters.
	 *
	 * @see SymmetricCipherUtil#initEncrypt(OutPut)
	 * @see SymmetricCipherUtil#processCipher(Cipher, InPut, OutPut)
	 * 
	 * @param mp Plain data Provider of source for encryption
	 * @param mc Data Consumer that writes encrypted data to designated destination 
	 * @throws NestedIOException if {@code IOException} is thrown. if this cipher process related with
	 * external resources(like {@code File}, caller should catch {@code NestedIOException}.
	 * @throws OmittedCipherException if a cipher-related, omitted exceptions that won't happen unless
	 * there's a internal flaw in the cipher library occurs.
	 * */
	@Override
	public void encrypt(InPut mp, OutPut mc) throws NestedIOException, OmittedCipherException {
		try (mp; mc) {
			processCipher(initEncrypt(mc), mp, mc);
		}
	}

	/**
	 * Decrypt from source(designated as <code>InPut</code>)
	 * and writes to given destination(designated as <code>OutPut</code>).
	 * <p>Default implementation calls two method {@link SymmetricCipherUtil#initDecrypt(InPut)},
	 * {@link SymmetricCipherUtil#processCipher(Cipher, InPut, OutPut)}, and close both parameters.
	 *
	 * @see SymmetricCipherUtil#initEncrypt(OutPut)
	 * @see SymmetricCipherUtil#processCipher(Cipher, InPut, OutPut)
	 * 
	 * @param mp Plain data Provider of source for encryption
	 * @param mc Data Consumer that writes encrypted data to designated destination 
	 * @throws NestedIOException if {@code IOException} is thrown. if this cipher process related with
	 * external resources(like {@code File}, caller should catch {@code NestedIOException}.  
	 * @throws OmittedCipherException if a cipher-related, omitted exceptions that won't happen unless
	 * there's a internal flaw in the cipher library occurs.
	 * */
	@Override
	public void decrypt(InPut mp, OutPut mc) throws NestedIOException, OmittedCipherException {
		try (mp; mc) {
			processCipher(initDecrypt(mp), mp, mc);
		}
	}
	
	/**
	 * Do Cipher Process with pre-initiated <code>cipher</code>.
	 * @param c The {@code Cipher} instance 
	 * @param mp Plain data Provider of source for encryption/decryption
	 * @param mc Data Consumer that writes encrypted/decryption data to designated destination 
	 * @throws NestedIOException if {@code IOException} is thrown. if this cipher process related with
	 * external resources(like {@code File}, caller should catch {@code NestedIOException}.  
	 * @throws OmittedCipherException if a cipher-related, omitted exceptions that won't happen unless
	 * there's a internal flaw in the cipher library occurs.
	 * */
	protected void processCipher(Cipher c, InPut mp, OutPut mc) throws NestedIOException, OmittedCipherException {
		byte[] buf = new byte[BUFFER_SIZE];
		while(updateCipher(c, buf, mp, mc) != -1) { }
		doFinalCipher(c, mc);
	}
	
	protected int updateCipher(Cipher c, byte[] buf, InPut mp, OutPut mc) {
		int read = mp.getSrc(buf);
		if(read == -1) return -1;
		byte[] result = c.update(buf, 0, read);
		if(result != null) mc.consumeResult(result);
		return read;
	}
	protected int doFinalCipher(Cipher c, OutPut mc) {
		try {
			byte[] res = c.doFinal();
			mc.consumeResult(res);
			return res.length;
		} catch (IllegalStateException | IllegalBlockSizeException | BadPaddingException e) {
			throw new OmittedCipherException(e);
		}
	}
	
	
	@Override
	public CipherTunnel cipherEncryptTunnel(InPut mp, OutPut mc) {
		return new CipherTunnel(initEncrypt(mc), mp, mc, BUFFER_SIZE) {
			@Override
			protected int update(Cipher cipher, byte[] buffer, InPut msgp, OutPut msgc) {
				return updateCipher(cipher, buffer, msgp, msgc);
			}
			@Override
			protected int doFinal(Cipher cipher, OutPut msgc) {
				return doFinalCipher(cipher, mc);
			}
		};
	}

	@Override
	public CipherTunnel cipherDecryptTunnel(InPut mp, OutPut mc) {
		return new CipherTunnel(initDecrypt(mp), mp, mc, BUFFER_SIZE) {
			@Override
			protected int update(Cipher cipher, byte[] buffer, InPut msgp, OutPut msgc) {
				return updateCipher(cipher, buffer, msgp, msgc);
			}
			@Override
			protected int doFinal(Cipher cipher, OutPut msgc) {
				return doFinalCipher(cipher, mc);
			}
		};
	}

	@Override
	public UpdatableEncrypter UpdatableEncryptCipher(OutPut mc) {
		return new UpdatableEncrypter(initEncrypt(mc), mc);
	}

	@Override
	public UpdatableDecrypter UpdatableDecryptCipher(InPut mp) {
		return new UpdatableDecrypter(initDecrypt(mp), mp, BUFFER_SIZE);
	}
	

	protected String fields() {
		Cipher c = getCipherInstance();
		return "\"" + c.getAlgorithm() + "\" from \"" + c.getProvider() + "\"";
	}
	
	@Override
	public String toString() {
		return getClass().getSimpleName() + " [" + fields() + "]";
	}
}
