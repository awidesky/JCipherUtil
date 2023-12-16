package io.github.awidesky.jCipherUtil.cipher;

import java.nio.ByteBuffer;

import javax.crypto.Cipher;
import javax.crypto.NullCipher;

import io.github.awidesky.jCipherUtil.AbstractCipherUtil;
import io.github.awidesky.jCipherUtil.exceptions.NestedIOException;
import io.github.awidesky.jCipherUtil.properties.CipherProperty;


/**
 * A null CipherUtil, which does not do any cipher process.
 * Output of encryption/decryption will identical with the input.
 * 
 * @see NullCipher
 * @since 1.3.0
 */
public class NullCipherUtil extends AbstractCipherUtil {

	private static final CipherProperty METADATA = new CipherProperty("no algorithm", "no mode", "no padding", "no key");
	
	/**
	 * Construct a NullCipherUtil object.
	 * @param bufferSize
	 */
	public NullCipherUtil(int bufferSize) {
		super(bufferSize);
	}

	@Override
	public CipherProperty getCipherProperty() {
		return METADATA;
	}


	/**
 	 * @return a new {@code NullCipher} object
	 */
	protected Cipher getCipherInstance() {
		return new NullCipher();
	}

	@Override
	protected Cipher initEncrypt(byte[] metadata) throws NestedIOException {
		return getCipherInstance();
	}

	@Override
	protected Cipher initDecrypt(ByteBuffer metadata) throws NestedIOException {
		return getCipherInstance();
	}

	/**
	 * NullCipherUtil does not have any metadata.
	 * @return 0
	 */
	@Override
	public int getMetadataLength() { return 0; }
	

	/**
	 * NullCipherUtil does not have any key, hence this method does nothing.
	 */
	@Override
	public void destroyKey() {}
	

	/**
	 * NullCipherUtil does not have any fields.
	 */
	protected String fields() {
		return "no fields";
	}

}
