package io.github.awidesky.jCipherUtil.cipher.symmetric.chacha20;

import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.spec.ChaCha20ParameterSpec;

import io.github.awidesky.jCipherUtil.cipher.symmetric.SymmetricCipherUtilBuilder;
import io.github.awidesky.jCipherUtil.cipher.symmetric.key.KeyMetadata;
import io.github.awidesky.jCipherUtil.cipher.symmetric.key.SymmetricKeyMaterial;
import io.github.awidesky.jCipherUtil.key.KeySize;
import io.github.awidesky.jCipherUtil.properties.CipherProperty;
import io.github.awidesky.jCipherUtil.properties.IVCipherProperty;

public class ChaCha20CipherUtil extends AbstractChaCha20CipherUtil {

	public final static IVCipherProperty METADATA = new IVCipherProperty("ChaCha20", "", "", "ChaCha20", 12);
	
	/**
	 * Construct this {@code ChaCha20CipherUtil} with given parameter.
	 * */
	private ChaCha20CipherUtil(CipherProperty cipherMetadata, KeyMetadata keyMetadata, KeySize keySize, SymmetricKeyMaterial key, int bufferSize) {
		super(cipherMetadata, keyMetadata, keySize, key, bufferSize);
	}
	/**
	 * Generate {@code AlgorithmParameterSpec} for this ChaCha20 cipher.
	 * Uses the <code>IV</code> for 12byte nonce, and 0 as initial counter value.
	 * */
	@Override
	protected AlgorithmParameterSpec getAlgorithmParameterSpec(byte[] nonce) {
		return new ChaCha20ParameterSpec(nonce, 0);
	}


	@Override
	protected IVCipherProperty getCipherProperty() { return METADATA; }

	
	public static class Builder extends SymmetricCipherUtilBuilder<ChaCha20CipherUtil> {
		
		public Builder(byte[] key, ChaCha20KeySize keySize) { super(key, keySize); }
		public Builder(char[] password, ChaCha20KeySize keySize) { super(password, keySize); }
		
		@Override
		public ChaCha20CipherUtil build() { return new ChaCha20CipherUtil(METADATA, keyMetadata, keySize, keyMet, bufferSize); }
		
	}
}
