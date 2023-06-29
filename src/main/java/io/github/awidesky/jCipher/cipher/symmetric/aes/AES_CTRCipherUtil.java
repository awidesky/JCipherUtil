package io.github.awidesky.jCipher.cipher.symmetric.aes;

import java.security.SecureRandom;
import java.util.Arrays;

import io.github.awidesky.jCipher.cipher.symmetric.SymmetricNonceCipherUtil;
import io.github.awidesky.jCipher.cipher.symmetric.key.SymmetricKeyMetadata;
import io.github.awidesky.jCipher.metadata.IVCipherProperty;

public class AES_CTRCipherUtil extends SymmetricNonceCipherUtil {

	public final static IVCipherProperty METADATA = new IVCipherProperty("AES", "CTR", "NoPadding", "AES", 16);
	
	/**
	 * Length of the counter in bytes.
	 * Counter will be reside in the least significant bits of the IV, and cannot be longer than 16byte.
	 * <code>counterLen</code> bytes of IV will be set to 0(zero).
	 * 4 byte of counter will handle at least 68GB of data without reusing the counter.
	 * */
	public final int counterLen;
	
	public AES_CTRCipherUtil(SymmetricKeyMetadata keyMetadata, int bufferSize) {
		super(METADATA, keyMetadata, bufferSize);
		counterLen = 4;
	}
	/**
	 * Initiate this object with given <code>counterLength</code>.
	 * 
	 * @throws IllegalArgumentException if <code>counterLength</code> is smaller than 1 or greater than 16.
	 * */
	public AES_CTRCipherUtil(SymmetricKeyMetadata keyMetadata, int bufferSize, int counterLength) {
		super(METADATA, keyMetadata, bufferSize);
		if(counterLength < 1 || 16 < counterLength) throw new IllegalArgumentException("Invalid counter length : " + counterLength + ", must be 0 < c < 17");
		this.counterLen = counterLength;
	}

	@Override
	protected void generateNonce(SecureRandom sr) {
		nonce = new byte[METADATA.NONCESIZE - counterLen];
		sr.nextBytes(nonce);
		nonce = Arrays.copyOfRange(nonce, 0, 16);
	}
	
	@Override
	protected IVCipherProperty getCipherProperty() { return METADATA; }

}
