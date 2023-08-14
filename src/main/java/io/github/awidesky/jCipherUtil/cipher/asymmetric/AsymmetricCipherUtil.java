package io.github.awidesky.jCipherUtil.cipher.asymmetric;

import java.security.InvalidKeyException;
import java.util.Optional;

import javax.crypto.Cipher;

import io.github.awidesky.jCipherUtil.AbstractCipherUtil;
import io.github.awidesky.jCipherUtil.cipher.asymmetric.key.AsymmetricKeyMaterial;
import io.github.awidesky.jCipherUtil.messageInterface.OutPut;
import io.github.awidesky.jCipherUtil.messageInterface.InPut;
import io.github.awidesky.jCipherUtil.properties.CipherProperty;
import io.github.awidesky.jCipherUtil.util.exceptions.IllegalMetadataException;
import io.github.awidesky.jCipherUtil.util.exceptions.NestedIOException;
import io.github.awidesky.jCipherUtil.util.exceptions.OmittedCipherException;

public abstract class AsymmetricCipherUtil extends AbstractCipherUtil {

	protected AsymmetricKeyMaterial key;

	public AsymmetricCipherUtil(CipherProperty cipherMetadata, AsymmetricKeyMaterial keyMet, int bufferSize) {
		super(cipherMetadata, bufferSize);
		this.key = keyMet;
	}

	@Override
	protected Cipher initEncrypt(OutPut mc) throws NestedIOException {
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
	protected Cipher initDecrypt(InPut mp) throws NestedIOException {
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
