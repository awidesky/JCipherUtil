package io.github.awidesky.jCipher.cipher.symmetric.aes;

import io.github.awidesky.jCipher.cipher.symmetric.SymmetricCipherUtil;
import io.github.awidesky.jCipher.cipher.symmetric.key.SymmetricKeyMetadata;
import io.github.awidesky.jCipher.properties.CipherProperty;

public class AES_ECBCipherUtil extends SymmetricCipherUtil {

	public final static CipherProperty METADATA = new CipherProperty("AES", "ECB", "PKCS5PADDING", "AES");
	
	/**
	 * Construct this {@code AES_ECBCipherUtil} with given {@code SymmetricKeyMetadata} and default buffer size.
	 * */
	public AES_ECBCipherUtil(SymmetricKeyMetadata keyMetadata) { super(METADATA, keyMetadata); }
	/**
	 * Construct this {@code AES_ECBCipherUtil} with given {@code SymmetricKeyMetadata} and buffer size.
	 * */
	public AES_ECBCipherUtil(SymmetricKeyMetadata keyMetadata, int bufferSize) { super(METADATA, keyMetadata, bufferSize); }

	@Override
	protected CipherProperty getCipherProperty() { return METADATA; }

}
