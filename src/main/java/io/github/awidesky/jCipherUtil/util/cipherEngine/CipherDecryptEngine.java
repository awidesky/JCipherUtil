package io.github.awidesky.jCipherUtil.util.cipherEngine;

import java.nio.ByteBuffer;
import java.util.Optional;
import java.util.function.Function;

import javax.crypto.Cipher;

import io.github.awidesky.jCipherUtil.messageInterface.InPut;
import io.github.awidesky.jCipherUtil.util.CipherMode;

/**
 * A {@code CipherDecryptEngine} is a {@code CipherEngine} subclass that used for decryption.
 */
public class CipherDecryptEngine extends CipherEngine {

	private ByteBuffer metadata;
	private Function<InPut, Cipher> init;

	public CipherDecryptEngine(CipherMode mode, Function<InPut, Cipher> init, int metadataLength) {
		super(mode);
		this.init = init;
		this.metadata = ByteBuffer.allocate(metadataLength);
	}

	
	private byte[] prepareMetadata(byte[] buf, int off, int len) {
		if(metadata.remaining() < len) {
			int remaining = metadata.remaining();
			metadata.put(buf, off, remaining);
			this.c = init.apply(InPut.from(metadata.array()));
			metadata = null;
			return Optional.ofNullable(c.update(buf, off + remaining, len - remaining)).orElse(new byte[0]);
		} else {
			metadata.put(buf, off, len);
			return new byte[0];
		}
	}
	//TODO : add abstract init() method, implement at AbstractCipherUtil.cipherEngine 
	@Override
	public byte[] update(byte[] buf, int off, int len) {
		if(finished) return null;
		if(metadata == null) {
			return Optional.ofNullable(c.update(buf, off, len)).orElse(new byte[0]);
		} else {
			return prepareMetadata(buf, off, len);
		}
	}

}
