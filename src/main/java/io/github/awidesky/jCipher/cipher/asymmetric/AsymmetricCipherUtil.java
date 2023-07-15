package io.github.awidesky.jCipher.cipher.asymmetric;

import java.security.InvalidKeyException;
import java.util.Optional;

import javax.crypto.Cipher;

import io.github.awidesky.jCipher.AbstractCipherUtil;
import io.github.awidesky.jCipher.cipher.asymmetric.key.AsymmetricKeyMaterial;
import io.github.awidesky.jCipher.messageInterface.MessageConsumer;
import io.github.awidesky.jCipher.messageInterface.MessageProvider;
import io.github.awidesky.jCipher.properties.CipherProperty;
import io.github.awidesky.jCipher.util.IllegalMetadataException;
import io.github.awidesky.jCipher.util.NestedIOException;
import io.github.awidesky.jCipher.util.OmittedCipherException;

public abstract class AsymmetricCipherUtil extends AbstractCipherUtil {

	protected AsymmetricKeyMaterial key;

	public AsymmetricCipherUtil(CipherProperty cipherMetadata, AsymmetricKeyMaterial keyMet, int bufferSize) {
		super(cipherMetadata, bufferSize);
		this.key = keyMet;
	}

	@Override
	protected Cipher initEncrypt(MessageConsumer mc) throws NestedIOException {
		try {
			Cipher c = getCipherInstance();
			c.init(Cipher.ENCRYPT_MODE, Optional.ofNullable(key.getKey(getCipherProperty().KEY_ALGORITMH_NAME).getPublic()).orElseThrow(
					() -> new IllegalMetadataException("This " + toString() + " instance does not have a public key!")));
			return c;
		} catch (InvalidKeyException e) {
			throw new OmittedCipherException(e);
		}
	}

	@Override
	protected Cipher initDecrypt(MessageProvider mp) throws NestedIOException {
		try {
			Cipher c = getCipherInstance();
			c.init(Cipher.DECRYPT_MODE, Optional.ofNullable(key.getKey(getCipherProperty().KEY_ALGORITMH_NAME).getPrivate()).orElseThrow(
					() -> new IllegalMetadataException("This " + toString() + " instance does not have a private key!")));
			return c;
		} catch (InvalidKeyException e) {
			throw new OmittedCipherException(e);
		}
	}
	

}
