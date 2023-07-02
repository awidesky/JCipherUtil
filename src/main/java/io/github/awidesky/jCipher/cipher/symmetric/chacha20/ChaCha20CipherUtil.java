package io.github.awidesky.jCipher.cipher.symmetric.chacha20;

import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.spec.ChaCha20ParameterSpec;

import io.github.awidesky.jCipher.cipher.symmetric.key.SymmetricKeyMetadata;
import io.github.awidesky.jCipher.properties.IVCipherProperty;

public class ChaCha20CipherUtil extends AbstractChaCha20CipherUtil {

	public final static IVCipherProperty METADATA = new IVCipherProperty("ChaCha20", "", "", "ChaCha20", 12);
	
	/**
	 * Construct this {@code ChaCha20CipherUtil} with given {@code SymmetricKeyMetadata} and default buffer size.
	 * */
	public ChaCha20CipherUtil(SymmetricKeyMetadata keyMetadata) {
		super(METADATA, keyMetadata);
	}
	/**
	 * Construct this {@code ChaCha20CipherUtil} with given {@code SymmetricKeyMetadata} and buffer size.
	 * */
	public ChaCha20CipherUtil(SymmetricKeyMetadata keyMetadata, int bufferSize) {
		super(METADATA, keyMetadata, bufferSize);
	}

	/**
	 * Generate {@code AlgorithmParameterSpec} for this ChaCha20 cipher.
	 * Uses the <code>IV</code> for 12byte nonce, and 0 as initial counter value.
	 * */
	@Override
	protected AlgorithmParameterSpec getAlgorithmParameterSpec() {
		return new ChaCha20ParameterSpec(nonce, 0);
	}


	@Override
	protected IVCipherProperty getCipherProperty() { return METADATA; }

}
