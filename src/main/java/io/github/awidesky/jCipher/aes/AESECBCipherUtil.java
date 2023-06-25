package io.github.awidesky.jCipher.aes;

import io.github.awidesky.jCipher.AbstractCipherUtil;
import io.github.awidesky.jCipher.metadata.CipherProperty;
import io.github.awidesky.jCipher.metadata.key.KeyMetadata;

public class AESECBCipherUtil extends AbstractCipherUtil {

	public final static CipherProperty METADATA = new CipherProperty("AES", "ECB", "PKCS5PADDING", "AES");
	
	public AESECBCipherUtil(KeyMetadata keyMetadata, int bufferSize) {
		super(METADATA, keyMetadata, bufferSize);
	}

	@Override
	protected CipherProperty getCipherProperty() { return METADATA; }

}
