package io.github.awidesky.jCipherUtil;

import java.nio.ByteBuffer;
import java.util.Optional;
import java.util.function.Function;

import javax.crypto.Cipher;

import io.github.awidesky.jCipherUtil.util.CipherMode;

/**
 * A {@code CipherDecryptEngine} is a {@code CipherEngine} subclass that used for decryption.
 */
public class CipherDecryptEngine extends CipherEngine {

	private ByteBuffer metadata;
	private Function<ByteBuffer, Cipher> cipherGenerator;

	CipherDecryptEngine(Function<ByteBuffer, Cipher> cipherGenerator, int metadataLength) {
		this.mode = CipherMode.DECRYPT_MODE;
		this.cipherGenerator = cipherGenerator;
		this.metadata = ByteBuffer.allocate(metadataLength);
	}

	
	private byte[] prepareMetadata(byte[] buf, int off, int len) {
		if(metadata.remaining() < len) {
			int remaining = metadata.remaining();
			metadata.put(buf, off, remaining);
			this.c = cipherGenerator.apply(metadata.flip());
			cipherGenerator = null;
			metadata = null;
			return Optional.ofNullable(c.update(buf, off + remaining, len - remaining)).orElse(new byte[0]);
		} else {
			metadata.put(buf, off, len);
			return new byte[0];
		}
	}
	@Override
	public byte[] update(byte[] buf, int off, int len) {
		if(finished) return null;
		if(metadata == null) {
			byte[] ret = c.update(buf, off, len);
			if(ret != null) return ret;
			else return new byte[0];
		} else {
			return prepareMetadata(buf, off, len);
		}
	}

}
