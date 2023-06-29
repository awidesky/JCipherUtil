package io.github.awidesky.jCipher.cipher.symmetric.chacha20;

import io.github.awidesky.jCipher.cipher.symmetric.key.SymmetricKeyMetadata;
import io.github.awidesky.jCipher.metadata.IVCipherProperty;

public class ChaCha20_Poly1305CipherUtil extends AbstractChaCha20CipherUtil {

	public final static IVCipherProperty METADATA = new IVCipherProperty("ChaCha20-Poly1305", "None", "NoPadding", "ChaCha20", 12);
	
	public ChaCha20_Poly1305CipherUtil(SymmetricKeyMetadata keyMetadata, int bufferSize) {
		super(METADATA, keyMetadata, bufferSize);
	}

	@Override
	protected IVCipherProperty getCipherProperty() { return METADATA; }

}
