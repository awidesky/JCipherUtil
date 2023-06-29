package io.github.awidesky.jCipher.cipher.asymmetric.key;

import io.github.awidesky.jCipher.metadata.KeyMetadata;
import io.github.awidesky.jCipher.metadata.KeySize;

public class AsymmetricKeyMetadata extends KeyMetadata {

	private AsymmetricKeyMetadata(KeySize keyLen) { super(keyLen); }

	public static AsymmetricKeyMetadata with(KeySize ks) {
		return new AsymmetricKeyMetadata(ks);
	}
}
