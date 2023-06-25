package io.github.awidesky.jCipher.cipher.symmetric.chacha20;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.IvParameterSpec;

import io.github.awidesky.jCipher.AbstractNonceCipherUtil;
import io.github.awidesky.jCipher.messageInterface.MessageProvider;
import io.github.awidesky.jCipher.metadata.CipherProperty;
import io.github.awidesky.jCipher.metadata.key.KeyMetadata;
import io.github.awidesky.jCipher.util.IllegalMetadataException;
import io.github.awidesky.jCipher.util.NestedIOException;
import io.github.awidesky.jCipher.util.OmittedCipherException;


/**
 * Some unknown stupid reason, {@code ChaCha20Ciper} in jdk does not let user initiate same cipher object with same key and nonce.
 * (see {@link https://github.com/openjdk/jdk/blob/master/src/java.base/share/classes/com/sun/crypto/provider/ChaCha20Cipher.java#L608})
 * How the hell am I going to decrypt stuff when I cannot reuse same key and nonce I used to encrypt the source??? 
 * <p>So, in here, I use a punt to avoid this <code>InvalidKeyException</code>, by initiating cipher with different nonce and key.
 * This will (hopefully) do the job...
 * */
public abstract class AbstractChaCha20CipherUtil extends AbstractNonceCipherUtil {

	protected AbstractChaCha20CipherUtil(CipherProperty cipherMetadata, KeyMetadata keyMetadata, int bufferSize) {
		super(cipherMetadata, keyMetadata, bufferSize);
	}


	@Override
	protected void initDecrypt(MessageProvider mp) throws NestedIOException {
		readIterationCount(mp);
		readSalt(mp);
		readNonce(mp);
		
		if (!(keyMetadata.iterationRange[0] <= iterationCount && iterationCount < keyMetadata.iterationRange[1])) {
			throw new IllegalMetadataException("Unacceptable iteration count : " + iterationCount + ", must between " + keyMetadata.iterationRange[0] + " and " + keyMetadata.iterationRange[1]);
		}
		try {
			/**Tweak IV and key*/
			byte[] iv = nonce.clone();
			//Tweak IV a little bit, making sure same IV not used again.
			iv[0] = (byte) ~iv[0];
			//generate random key too. Key iteration process would consume much time.
			KeyGenerator sf = KeyGenerator.getInstance(getCipherProperty().KEY_ALGORITMH_NAME);
			sf.init(keyMetadata.keyLen);
			cipher.init(Cipher.ENCRYPT_MODE, sf.generateKey(), new IvParameterSpec(iv));
			/**Tweak IV and key*/
			
			cipher.init(Cipher.DECRYPT_MODE, key.genKey(getCipherProperty().KEY_ALGORITMH_NAME, keyMetadata.keyLen, salt, iterationCount), getAlgorithmParameterSpec());
		} catch (InvalidKeyException | InvalidAlgorithmParameterException | NoSuchAlgorithmException e) {
			throw new OmittedCipherException(e);
		}
	}

	
}
