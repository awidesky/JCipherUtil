package io.github.awidesky.jCipherUtil.cipher.symmetric.aes;

import io.github.awidesky.jCipherUtil.cipher.symmetric.SymmetricCipherUtil;
import io.github.awidesky.jCipherUtil.cipher.symmetric.SymmetricCipherUtilBuilder;
import io.github.awidesky.jCipherUtil.cipher.symmetric.key.KeyMetadata;
import io.github.awidesky.jCipherUtil.cipher.symmetric.key.SymmetricKeyMaterial;
import io.github.awidesky.jCipherUtil.key.KeySize;
import io.github.awidesky.jCipherUtil.properties.CipherProperty;


public class AES_ECBCipherUtil extends SymmetricCipherUtil {

	public final static CipherProperty METADATA = new CipherProperty("AES", "ECB", "PKCS5PADDING", "AES");
	
	/**
	 * Construct this {@code AES_GCMCipherUtil} with given parameters.
	 * */
	private AES_ECBCipherUtil(CipherProperty cipherMetadata, KeyMetadata keyMetadata, KeySize keySize, SymmetricKeyMaterial key, int bufferSize) {
		super(cipherMetadata, keyMetadata, keySize, key, bufferSize);
	}
	
	@Override
	protected CipherProperty getCipherProperty() { return METADATA; }

	public static class Builder extends SymmetricCipherUtilBuilder<AES_ECBCipherUtil> {
		
		public Builder(byte[] key, AESKeySize keySize) { super(key, keySize); }
		public Builder(char[] password, AESKeySize keySize) { super(password, keySize); }
		
		@Override
		public AES_ECBCipherUtil build() { return new AES_ECBCipherUtil(METADATA, keyMetadata, keySize, keyMet, bufferSize); }
		
	}

}


