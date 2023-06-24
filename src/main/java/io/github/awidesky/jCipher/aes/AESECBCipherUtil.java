package io.github.awidesky.jCipher.aes;

import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.SecureRandom;

import javax.crypto.Cipher;

import io.github.awidesky.jCipher.AbstractCipherUtil;
import io.github.awidesky.jCipher.messageInterface.MessageConsumer;
import io.github.awidesky.jCipher.messageInterface.MessageProvider;
import io.github.awidesky.jCipher.metadata.CipherProperty;
import io.github.awidesky.jCipher.metadata.key.KeyMetadata;
import io.github.awidesky.jCipher.util.IllegalMetadataException;
import io.github.awidesky.jCipher.util.NestedIOException;
import io.github.awidesky.jCipher.util.OmittedCipherException;

public class AESECBCipherUtil extends AbstractCipherUtil {

	public final static CipherProperty METADATA = new CipherProperty("AES", "ECB", "PKCS5PADDING", "AES", 0);
	
	public AESECBCipherUtil(KeyMetadata keyMetadata, int bufferSize) {
		super(METADATA, keyMetadata, bufferSize);
	}


	@Override
	protected CipherProperty getCipherMetadata() { return METADATA; }


	@Override
	protected void initEncrypt(MessageConsumer mc) throws NestedIOException {
		SecureRandom sr = new SecureRandom();
		generateSalt(sr);
		generateIterationCount(sr);
		try {
			cipher.init(Cipher.ENCRYPT_MODE, key.genKey(getCipherMetadata().KEY_ALGORITMH_NAME, keyMetadata.keyLen, salt, iterationCount));
		} catch (InvalidKeyException e) {
			throw new OmittedCipherException(e);
		}
		mc.consumeResult(ByteBuffer.allocate(4).putInt(iterationCount).array());
		mc.consumeResult(salt);
	}


	@Override
	protected void initDecrypt(MessageProvider mp) throws NestedIOException {
		readIterationCount(mp);
		readSalt(mp);
		
		if (!(keyMetadata.iterationRange[0] <= iterationCount && iterationCount < keyMetadata.iterationRange[1])) {
			throw new IllegalMetadataException("Unacceptable iteration count : " + iterationCount + ", must between " + keyMetadata.iterationRange[0] + " and " + keyMetadata.iterationRange[1]);
		}
		try {
			cipher.init(Cipher.DECRYPT_MODE, key.genKey(getCipherMetadata().KEY_ALGORITMH_NAME, keyMetadata.keyLen, salt, iterationCount));
		} catch (InvalidKeyException e) {
			throw new OmittedCipherException(e);
		}		
	}


}
