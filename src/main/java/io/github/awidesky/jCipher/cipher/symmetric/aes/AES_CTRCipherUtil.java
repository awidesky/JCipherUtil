package io.github.awidesky.jCipher.cipher.symmetric.aes;

import java.security.SecureRandom;
import java.util.Arrays;

import io.github.awidesky.jCipher.cipher.symmetric.SymmetricCipherUtilBuilder;
import io.github.awidesky.jCipher.cipher.symmetric.SymmetricNonceCipherUtil;
import io.github.awidesky.jCipher.cipher.symmetric.key.SymmetricKeyMaterial;
import io.github.awidesky.jCipher.cipher.symmetric.key.SymmetricKeyMetadata;
import io.github.awidesky.jCipher.key.KeySize;
import io.github.awidesky.jCipher.properties.CipherProperty;
import io.github.awidesky.jCipher.properties.IVCipherProperty;

public class AES_CTRCipherUtil extends SymmetricNonceCipherUtil {

	public final static IVCipherProperty METADATA = new IVCipherProperty("AES", "CTR", "NoPadding", "AES", 16);
	
	/**
	 * Length of the counter in bytes.
	 * Counter will be reside in the least significant bits of the IV, and cannot be longer than 16byte.
	 * <code>counterLen</code> bytes of IV will be set to 0(zero).
	 * 4 byte of counter will handle at least 68GB of data without reusing the counter.
	 * */
	public final int counterLen;
	
	private AES_CTRCipherUtil(CipherProperty cipherMetadata, SymmetricKeyMetadata keyMetadata, KeySize keySize, SymmetricKeyMaterial key, int bufferSize) {
		this(cipherMetadata, keyMetadata, keySize, key, bufferSize, 4);
	}

	/**
	 * Initiate this object with given <code>counterLength</code>.
	 * 
	 * @throws IllegalArgumentException if <code>counterLength</code> is smaller than 1 or greater than 16.
	 * */
	private AES_CTRCipherUtil(CipherProperty cipherMetadata, SymmetricKeyMetadata keyMetadata, KeySize keySize, SymmetricKeyMaterial key, int bufferSize, int counterLength) {
		super(cipherMetadata, keyMetadata, keySize, key, bufferSize);
		if(counterLength < 1 || 16 < counterLength) throw new IllegalArgumentException("Invalid counter length : " + counterLength + ", must be 0 < c < 17");
		this.counterLen = counterLength;
	}

	@Override
	protected byte[] generateNonce(SecureRandom sr) {
		byte[] nonce = new byte[METADATA.NONCESIZE - counterLen];
		sr.nextBytes(nonce);
		nonce = Arrays.copyOfRange(nonce, 0, 16);
		return nonce;
	}
	
	@Override
	protected IVCipherProperty getCipherProperty() { return METADATA; }


	public static class Builder extends SymmetricCipherUtilBuilder {
		
		public Builder(byte[] key, AESKeySize keySize) { super(key, keySize); }
		public Builder(char[] password, AESKeySize keySize) { super(password, keySize); }
		
		@Override
		public AES_CTRCipherUtil build() { return new AES_CTRCipherUtil(METADATA, keyMetadata, keySize, keyMet, bufferSize); }
		
	}
}
