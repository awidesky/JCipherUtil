package io.github.awidesky.jCipherUtil.cipher.symmetric.chacha20;

import java.nio.ByteBuffer;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;

import io.github.awidesky.jCipherUtil.cipher.symmetric.SymmetricNonceCipherUtil;
import io.github.awidesky.jCipherUtil.cipher.symmetric.key.KeyMetadata;
import io.github.awidesky.jCipherUtil.cipher.symmetric.key.SymmetricKeyMaterial;
import io.github.awidesky.jCipherUtil.exceptions.IllegalMetadataException;
import io.github.awidesky.jCipherUtil.exceptions.NestedIOException;
import io.github.awidesky.jCipherUtil.exceptions.OmittedCipherException;
import io.github.awidesky.jCipherUtil.key.KeySize;


/**
 * A superclass for ChaCha20 {@code CipherUtil}.
 * <p>
 * Notes : Some unknown stupid reason, {@code ChaCha20Ciper} in JDK does not let user initiate same cipher object with same key and nonce, <i><b>no matter encrypting or decrypting</b></i>.
 * (see <a href="https://github.com/openjdk/jdk/blob/master/src/java.base/share/classes/com/sun/crypto/provider/ChaCha20Cipher.java#L608">https://github.com/openjdk/jdk/blob/master/src/java.base/share/classes/com/sun/crypto/provider/ChaCha20Cipher.java#L608</a>)
 * How the hell am I going to decrypt stuff when I cannot reuse same key and nonce I used to encrypt the source??? 
 * <p>So, in here, I use a punt to avoid this <code>InvalidKeyException</code>, by initiating cipher with different nonce and key.
 * This will (hopefully) do the job...
 * */
public abstract class AbstractChaCha20CipherUtil extends SymmetricNonceCipherUtil {
	

	/**
	 * Construct this {@code AbstractChaCha20CipherUtil} with given parameters.
	 * */
	public AbstractChaCha20CipherUtil(KeyMetadata keyMetadata, KeySize keySize, SymmetricKeyMaterial key, int bufferSize) {
		super(keyMetadata, keySize, key, bufferSize);
	}

	/**
	 * Before decrypt operation, target encrypted data might just encrypted via ChaCha20 cipher.
	 * In this case, IV and key is as same as previous {@code ChaCha20Cipher}(sun's {@code CipherSpi} subclass in the JDK) initialization, and 
	 * {@code ChaCha20Cipher} will throw "{@code InvalidKeyException : Matching key and nonce from previous initialization}".
	 * To prevent this, after reading the IV from input, {@code Cipher#init()} will be invoked with tweaked IV and random key before initiating with real ones.
	 * <p>(see <a href="https://github.com/openjdk/jdk/blob/master/src/java.base/share/classes/com/sun/crypto/provider/ChaCha20Cipher.java#L608">https://github.com/openjdk/jdk/blob/master/src/java.base/share/classes/com/sun/crypto/provider/ChaCha20Cipher.java#L608</a>)
	 * <p>Note : Only {@code initDecrypt} method is overridden because encryption doesn't need this process. You should not encrypt with same IV and key as previous encrypt/decrypt.
	 * THAT is a case {@code ChaCha20Cipher} had tried to forbid in it's intention.
	 * 
	 * @throws NestedIOException When one of the following is thrown : {@code InvalidKeyException, InvalidAlgorithmParameterException, NoSuchAlgorithmException}.
	 * */
	@Override
	protected Cipher initDecrypt(ByteBuffer metadata) throws NestedIOException {
		byte[] salt = new byte[keyMetadata.saltLen];
		byte[] nonce = new byte[getCipherProperty().NONCESIZE];
		int iterationCount = metadata.clear().getInt();
		metadata.get(salt);
		metadata.get(nonce);
		
		if (!(keyMetadata.iterationRangeStart <= iterationCount && iterationCount < keyMetadata.iterationRangeEnd)) {
			throw new IllegalMetadataException("Unacceptable iteration count : " + iterationCount + ", must between " + keyMetadata.iterationRangeStart + " and " + keyMetadata.iterationRangeEnd);
		}
		Cipher c = getCipherInstance();
		try {
			/** Tweak IV and make random key */
			//Tweak IV a little bit, making sure same IV not used again.
			nonce[0] = (byte) ~nonce[0];
			//Generate random key without use of ByteArrayKeyMaterial. 
			//Key iteration process would consume much more time.
			KeyGenerator sf = KeyGenerator.getInstance(getCipherProperty().KEY_ALGORITMH_NAME);
			sf.init(keySize.value);
			initCipherInstance(c, Cipher.ENCRYPT_MODE, sf.generateKey(), getAlgorithmParameterSpec(nonce));
			
			//Re-invert the first bit
			nonce[0] = (byte) ~nonce[0];
			/** initialize with actual key and IV */
			initCipherInstance(c, Cipher.DECRYPT_MODE, key.genKey(getCipherProperty().KEY_ALGORITMH_NAME, keySize.value, salt, iterationCount), getAlgorithmParameterSpec(nonce));
		} catch (Exception e) {
			throw new OmittedCipherException(e);
		}
		return c;
	}

	
}
