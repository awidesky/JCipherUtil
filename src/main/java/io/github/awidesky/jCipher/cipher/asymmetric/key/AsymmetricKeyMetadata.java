package io.github.awidesky.jCipher.cipher.asymmetric.key;

import io.github.awidesky.jCipher.key.KeyMetadata;
import io.github.awidesky.jCipher.key.KeySize;

public class AsymmetricKeyMetadata extends KeyMetadata {

	private AsymmetricKeyMetadata(KeySize keyLen) { super(keyLen); }

	public static AsymmetricKeyMetadata with(KeySize ks) {
		return new AsymmetricKeyMetadata(ks);
	}
}
