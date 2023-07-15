package io.github.awidesky.jCipher;

import java.io.ByteArrayOutputStream;
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

	protected final int BUFFER_SIZE;
	protected final CipherProperty cipherMetadata;
	
	/**
	 * Construct this {@code AbstractCipherUtil} with given {@code CipherProperty} and buffer size.
	 * */
	public AbstractCipherUtil(CipherProperty cipherMetadata, int bufferSize) {
		this.cipherMetadata = cipherMetadata;
		this.BUFFER_SIZE = bufferSize;
	}
	
	protected Cipher getCipherInstance() {
		try {
			return Cipher.getInstance(getCipherProperty().ALGORITMH_NAME + "/" + getCipherProperty().ALGORITMH_MODE + "/" + getCipherProperty().ALGORITMH_PADDING);
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
	 * to {@code MessageConsumer}.
	 * This method can be override to generate and write additional metadata(like Initial Vector)
	 * @throws NestedIOException if {@code IOException} is thrown.
	 * */
	protected abstract Cipher initEncrypt(MessageConsumer mc) throws NestedIOException;

	/**
	 * Initialize <code>Cipher</code> in decrypt mode so that it can be usable(be able to call <code>cipher.update</code>, <code>cipher.doFinal</code>
	 * In default, this method reads iteration count and salt from {@code MessageProvider}, and initiate the <code>Cipher</code> instance
	 * .
	 * This method can be override to read additional metadata(like Initial Vector) from {@code MessageConsumer} 
	 * @throws NestedIOException if {@code IOException} is thrown.
	 * */
	protected abstract Cipher initDecrypt(MessageProvider mp) throws NestedIOException;


	
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
			processCipher(initEncrypt(mc), mp, mc);
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
	protected void processCipher(Cipher c, MessageProvider mp, MessageConsumer mc) throws NestedIOException, OmittedCipherException {
		byte[] buf = new byte[BUFFER_SIZE];
		while(updateCipher(c, buf, mp, mc) != -1) { }
		doFinal(c, mc);
	}
	
	protected int updateCipher(Cipher c, byte[] buf, MessageProvider mp, MessageConsumer mc) {
		int read = mp.getSrc(buf);
		if(read == -1) return -1;
		byte[] result = c.update(buf, 0, read);
		if(result != null) mc.consumeResult(result);
		return read;
	}
	protected int doFinal(Cipher c, MessageConsumer mc) {
		try {
			byte[] res = c.doFinal();
			mc.consumeResult(res);
			return res.length;
		} catch (IllegalStateException | IllegalBlockSizeException | BadPaddingException e) {
			throw new OmittedCipherException(e);
		}
	}
	
	
	@Override
	public CipherTunnel cipherEncryptTunnel(MessageProvider mp, MessageConsumer mc) {
		return new CipherTunnel(initEncrypt(mc), mp, mc, BUFFER_SIZE) {
			@Override
			public int transfer() {
				return updateCipher(c, buf, mp, mc);
			}
			@Override
			public int transferFinal() { //TODO : 코드 재사용? 
				int read = 0;
				int total = 0;
				while(true) {
					read = updateCipher(c, buf, mp, mc);
					if(read == -1) break;
					total += read;
				}
				total += doFinal(c, mc);
				return total;
			}
		};
	}

	@Override
	public CipherTunnel cipherDecryptTunnel(MessageProvider mp, MessageConsumer mc) {
		return new CipherTunnel(initDecrypt(mp), mp, mc, BUFFER_SIZE) {
			@Override
			public int transfer() {
				return updateCipher(c, buf, mp, mc);
			}
			@Override
			public int transferFinal() {
				int read = 0;
				int total = 0;
				while(true) {
					read = updateCipher(c, buf, mp, mc);
					if(read == -1) break;
					total += read;
				}
				total += doFinal(c, mc);
				return total;
			}
		};
	}

	@Override
	public UpdatableEncrypter UpdatableEncryptCipher(MessageConsumer mc) {
		return new UpdatableEncrypter(initEncrypt(mc), mc, BUFFER_SIZE) {
			@Override
			public int update(byte[] buf) {
				byte[] result = c.update(buf);
				if(result != null) mc.consumeResult(result);
				return result.length;
			}
			
			@Override
			public int doFinal(byte[] buf) {
				try {
					byte[] result = c.doFinal(buf);
					mc.consumeResult(result);
					return result.length;
				} catch (IllegalBlockSizeException | BadPaddingException | NestedIOException e) {
					throw new OmittedCipherException(e);
				}
			}
		};
	}

	@Override
	public UpdatableDecrypter UpdatableDecryptCipher(MessageProvider mp) {
		return new UpdatableDecrypter(initDecrypt(mp), mp, BUFFER_SIZE) {
			@Override
			public byte[] update() {
				int read = mp.getSrc(buf);
				if(read == -1) return null;
				return c.update(buf, 0, read);
			}
			
			@Override
			public byte[] doFinal() {
				ByteArrayOutputStream bao = new ByteArrayOutputStream();
				while(true) {
					byte[] b = update();
					if(b == null) break;
					bao.writeBytes(b);
				}
				try {
					bao.writeBytes(c.doFinal());
				} catch (IllegalBlockSizeException | BadPaddingException e) {
					throw new OmittedCipherException(e);
				}
				return bao.toByteArray();
			}
		};
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
