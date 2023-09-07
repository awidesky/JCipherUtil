package io.github.awidesky.jCipherUtil.cipher.symmetric.aes;

import io.github.awidesky.jCipherUtil.cipher.symmetric.SymmetricCipherUtil;
import io.github.awidesky.jCipherUtil.cipher.symmetric.SymmetricCipherUtilBuilder;
import io.github.awidesky.jCipherUtil.cipher.symmetric.key.ByteArrayKeyMaterial;
import io.github.awidesky.jCipherUtil.cipher.symmetric.key.KeyMetadata;
import io.github.awidesky.jCipherUtil.cipher.symmetric.key.PasswordKeyMaterial;
import io.github.awidesky.jCipherUtil.cipher.symmetric.key.SymmetricKeyMaterial;
import io.github.awidesky.jCipherUtil.key.KeySize;
import io.github.awidesky.jCipherUtil.properties.CipherProperty;

/**
 * A AES/ECB/PKCS5PADDING {@code CipherUtil}.
 * */
public class AES_ECBCipherUtil extends SymmetricCipherUtil {

	public final static CipherProperty METADATA = new CipherProperty("AES", "ECB", "PKCS5PADDING", "AES");
	
	/**
	 * Construct this {@code AES_GCMCipherUtil} with given parameters.
	 * */
	private AES_ECBCipherUtil(KeyMetadata keyMetadata, KeySize keySize, SymmetricKeyMaterial key, int bufferSize) {
		super(keyMetadata, keySize, key, bufferSize);
	}
	
	@Override
	protected CipherProperty getCipherProperty() { return METADATA; }

	public static class Builder extends SymmetricCipherUtilBuilder<AES_ECBCipherUtil> {
		
		/**
		 * Specify binary private key data and AES key value.
		 * <p>The private key data is <b>not</b> directly used as an AES key. Instead it will salted and hashed
		 * multiple times.
		 * 
		 * @see ByteArrayKeyMaterial#ByteArrayKeyMaterial(byte[])
		 * */
		public Builder(byte[] key, AESKeySize keySize) { super(key, keySize); }
		/**
		 * Specify password and AES key value.
		 * 
		 * @see PasswordKeyMaterial#PasswordKeyMaterial(char[])
		 * */
		public Builder(char[] password, AESKeySize keySize) { super(password, keySize); }
		
		/**
		 * Returns generated {@code AES_ECBCipherUtil}.
		 * */
		@Override
		public AES_ECBCipherUtil build() { return new AES_ECBCipherUtil(keyMetadata, keySize, keyMet, bufferSize); }
		
	}

}


