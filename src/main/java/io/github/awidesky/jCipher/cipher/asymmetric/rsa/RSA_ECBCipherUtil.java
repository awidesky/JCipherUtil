package io.github.awidesky.jCipher.cipher.asymmetric.rsa;

import io.github.awidesky.jCipher.cipher.asymmetric.AsymmetricCipherUtil;
import io.github.awidesky.jCipher.key.KeyMetadata;
import io.github.awidesky.jCipher.properties.CipherProperty;

public class RSA_ECBCipherUtil extends AsymmetricCipherUtil {

	public final static CipherProperty METADATA = new CipherProperty("RSA", "ECB", "PKCS1Padding", "RSA");
	
	
	public RSA_ECBCipherUtil(KeyMetadata keyMetadata) {
		super(METADATA, keyMetadata);
	}
	public RSA_ECBCipherUtil(KeyMetadata keyMetadata, int bufferSize) {
		super(METADATA, keyMetadata, bufferSize);
	}

	@Override
	protected CipherProperty getCipherProperty() { return METADATA; }

}
