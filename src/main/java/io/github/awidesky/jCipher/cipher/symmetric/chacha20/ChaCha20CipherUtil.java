package io.github.awidesky.jCipher.cipher.symmetric.chacha20;

import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.spec.ChaCha20ParameterSpec;

import io.github.awidesky.jCipher.metadata.IVCipherProperty;
import io.github.awidesky.jCipher.metadata.key.KeyMetadata;

public class ChaCha20CipherUtil extends AbstractChaCha20CipherUtil {

	public final static IVCipherProperty METADATA = new IVCipherProperty("ChaCha20", "", "", "ChaCha20", 12);
	
	public ChaCha20CipherUtil(KeyMetadata keyMetadata, int bufferSize) {
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
