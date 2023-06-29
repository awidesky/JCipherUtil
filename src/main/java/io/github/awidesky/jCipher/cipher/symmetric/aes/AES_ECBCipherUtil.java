package io.github.awidesky.jCipher.cipher.symmetric.aes;

import io.github.awidesky.jCipher.cipher.symmetric.SymmetricCipherUtil;
import io.github.awidesky.jCipher.cipher.symmetric.key.SymmetricKeyMetadata;
import io.github.awidesky.jCipher.metadata.CipherProperty;

public class AES_ECBCipherUtil extends SymmetricCipherUtil {

	public final static CipherProperty METADATA = new CipherProperty("AES", "ECB", "PKCS5PADDING", "AES");
	
	public AES_ECBCipherUtil(SymmetricKeyMetadata keyMetadata, int bufferSize) {
		super(METADATA, keyMetadata, bufferSize);
	}

	@Override
	protected CipherProperty getCipherProperty() { return METADATA; }

}
