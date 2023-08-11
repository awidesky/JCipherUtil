package io.github.awidesky.jCipherUtil.cipher.symmetric.chacha20;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;

import io.github.awidesky.jCipherUtil.cipher.symmetric.SymmetricNonceCipherUtil;
import io.github.awidesky.jCipherUtil.cipher.symmetric.key.KeyMetadata;
import io.github.awidesky.jCipherUtil.cipher.symmetric.key.SymmetricKeyMaterial;
import io.github.awidesky.jCipherUtil.key.KeySize;
import io.github.awidesky.jCipherUtil.messageInterface.MessageProvider;
import io.github.awidesky.jCipherUtil.properties.CipherProperty;
import io.github.awidesky.jCipherUtil.util.exceptions.IllegalMetadataException;
import io.github.awidesky.jCipherUtil.util.exceptions.NestedIOException;
import io.github.awidesky.jCipherUtil.util.exceptions.OmittedCipherException;


/**
 * Some unknown stupid reason, {@code ChaCha20Ciper} in jdk does not let user initiate same cipher object with same key and nonce.
 * (see @see <a href="https://github.com/openjdk/jdk/blob/master/src/java.base/share/classes/com/sun/crypto/provider/ChaCha20Cipher.java#L608">https://github.com/openjdk/jdk/blob/master/src/java.base/share/classes/com/sun/crypto/provider/ChaCha20Cipher.java#L608</a>)
 * How the hell am I going to decrypt stuff when I cannot reuse same key and nonce I used to encrypt the source??? 
 * <p>So, in here, I use a punt to avoid this <code>InvalidKeyException</code>, by initiating cipher with different nonce and key.
 * This will (hopefully) do the job...
 * */
public abstract class AbstractChaCha20CipherUtil extends SymmetricNonceCipherUtil {
	

	/**
	 * Construct this {@code AbstractChaCha20CipherUtil} with given parameters.
	 * */
	public AbstractChaCha20CipherUtil(CipherProperty cipherMetadata, KeyMetadata keyMetadata, KeySize keySize, SymmetricKeyMaterial key, int bufferSize) {
		super(cipherMetadata, keyMetadata, keySize, key, bufferSize);
	}


	@Override
	protected Cipher initDecrypt(MessageProvider mp) throws NestedIOException {
		int iterationCount = readIterationCount(mp);
		byte[] salt = readSalt(mp);
		byte[] nonce = readNonce(mp);
		
		if (!(keyMetadata.iterationRange[0] <= iterationCount && iterationCount < keyMetadata.iterationRange[1])) {
			throw new IllegalMetadataException("Unacceptable iteration count : " + iterationCount + ", must between " + keyMetadata.iterationRange[0] + " and " + keyMetadata.iterationRange[1]);
		}
		Cipher c = getCipherInstance();
		try {
			/**Tweak IV and key*/
			byte[] iv = nonce.clone();
			//Tweak IV a little bit, making sure same IV not used again.
			iv[0] = (byte) ~iv[0];
			//generate random key too. Key iteration process would consume much time.
			KeyGenerator sf = KeyGenerator.getInstance(getCipherProperty().KEY_ALGORITMH_NAME);
			sf.init(keySize.size);
			c.init(Cipher.ENCRYPT_MODE, sf.generateKey(), getAlgorithmParameterSpec(iv));
			/**Tweak IV and key*/
			
			c.init(Cipher.DECRYPT_MODE, key.genKey(getCipherProperty().KEY_ALGORITMH_NAME, keySize.size, salt, iterationCount), getAlgorithmParameterSpec(nonce));
		} catch (InvalidKeyException | InvalidAlgorithmParameterException | NoSuchAlgorithmException e) {
			throw new OmittedCipherException(e);
		}
		return c;
	}

	
}
