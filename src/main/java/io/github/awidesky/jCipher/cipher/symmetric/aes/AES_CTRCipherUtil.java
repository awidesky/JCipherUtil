package io.github.awidesky.jCipher.cipher.symmetric.aes;

import java.security.SecureRandom;
import java.util.Arrays;

import io.github.awidesky.jCipher.AbstractIVCipherUtil;
import io.github.awidesky.jCipher.metadata.IVCipherProperty;
import io.github.awidesky.jCipher.metadata.key.KeyMetadata;

public class AES_CTRCipherUtil extends AbstractIVCipherUtil {

	public final static IVCipherProperty METADATA = new IVCipherProperty("AES", "CTR", "NoPadding", "AES", 16);
	
	/**
	 * Length of the counter in bytes.
	 * Counter will be reside in the least significant bits of the IV, and cannot be longer than 16byte.
	 * <code>counterLen</code> bytes of IV will be set to 0(zero).
	 * 4 byte of counter will handle at least 68GB of data without reusing the counter.
	 * */
	public final int counterLen; //TODO : add specific tests(like invalid counter length..) 
	
	public AES_CTRCipherUtil(KeyMetadata keyMetadata, int bufferSize) {
		super(METADATA, keyMetadata, bufferSize);
		counterLen = 4;
	}
	public AES_CTRCipherUtil(KeyMetadata keyMetadata, int bufferSize, int counterLength) {
		super(METADATA, keyMetadata, bufferSize);
		this.counterLen = counterLength;
	}

	@Override
	protected void generateIV(SecureRandom sr) {
		byte[] nonce = new byte[16 - counterLen];
		sr.nextBytes(nonce);
		IV = Arrays.copyOfRange(nonce, 0, 16);
	}
	
	@Override
	protected IVCipherProperty getCipherProperty() { return METADATA; }

}
