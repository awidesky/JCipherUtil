package io.github.awidesky.jCipherUtil.util.cipherEngine;

import java.nio.ByteBuffer;
import java.util.Optional;
import java.util.function.Function;

import javax.crypto.Cipher;

import io.github.awidesky.jCipherUtil.CipherUtil.CipherMode;
import io.github.awidesky.jCipherUtil.messageInterface.InPut;

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
			init();
			metadata = null;
			return Optional.ofNullable(c.update(buf, off + remaining, len - remaining)).orElse(new byte[0]);
		} else {
			metadata.put(buf, off, len);
			return new byte[0];
		}
	}
	
	@Override
	public void init() {
		this.c = init.apply(InPut.from(metadata.array()));
	}
	@Override
	public byte[] update(byte[] buf, int off, int len) {
		if(metadata == null) {
			return Optional.ofNullable(c.update(buf, off, len)).orElse(new byte[0]);
		} else {
			return prepareMetadata(buf, off, len);
		}
	}

}
