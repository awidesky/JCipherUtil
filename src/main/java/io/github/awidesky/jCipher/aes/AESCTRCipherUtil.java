package io.github.awidesky.jCipher.aes;

import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;

import javax.crypto.spec.IvParameterSpec;

import io.github.awidesky.jCipher.AbstractCipherUtilWithNonce;
import io.github.awidesky.jCipher.metadata.CipherProperty;
import io.github.awidesky.jCipher.metadata.key.KeyMetadata;

public class AESCTRCipherUtil extends AbstractCipherUtilWithNonce {

	public final static CipherProperty METADATA = new CipherProperty("AES", "CTR", "NoPadding", "AES", 16);
	
	/**
	 * Length of the counter in bytes.
	 * Counter will be reside in the least significant bits of the IV, and cannot be longer than 16byte.
	 * <code>counterLen</code> bytes of IV will be set to 0(zero).
	 * 4 byte of counter will handle at least 68GB of data without reusing the counter.
	 * */
	public final int counterLen; //TODO : add specific tests(like invalid counter length..) 
	
	public AESCTRCipherUtil(KeyMetadata keyMetadata, int bufferSize) {
		super(METADATA, keyMetadata, bufferSize);
		counterLen = 4;
	}
	public AESCTRCipherUtil(KeyMetadata keyMetadata, int bufferSize, int counterLength) {
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
	protected AlgorithmParameterSpec getAlgorithmParameterSpec() {
		return new IvParameterSpec(IV);
	}

	@Override
	protected CipherProperty getCipherMetadata() { return METADATA; }

}
