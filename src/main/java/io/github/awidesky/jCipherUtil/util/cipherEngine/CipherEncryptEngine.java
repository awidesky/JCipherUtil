package io.github.awidesky.jCipherUtil.util.cipherEngine;

import java.io.ByteArrayOutputStream;
import java.util.Optional;
import java.util.function.Function;

import javax.crypto.Cipher;

import io.github.awidesky.jCipherUtil.messageInterface.OutPut;
import io.github.awidesky.jCipherUtil.util.CipherMode;

/**
 * A {@code CipherEncryptEngine} is a {@code CipherEngine} subclass that used for encryption.
 */
public class CipherEncryptEngine extends CipherEngine {

	private byte[] metadata = null;

	public CipherEncryptEngine(CipherMode mode, Function<OutPut, Cipher> init, int metadataSize) {
		super(mode);
		ByteArrayOutputStream o = new ByteArrayOutputStream(metadataSize);
		this.c = init.apply(OutPut.to(o));
		metadata = o.toByteArray();
	}
	
	@Override
	public byte[] update(byte[] buf, int off, int len) {
		if(finished) return null;
		if(metadata == null) {
			return Optional.ofNullable(c.update(buf, off, len)).orElse(new byte[0]);
		} else {
			ByteArrayOutputStream o = new ByteArrayOutputStream();
			o.write(metadata, 0, metadata.length);
			metadata = null;
			byte[] extra = Optional.ofNullable(c.update(buf, off, len)).orElse(new byte[0]);
			o.write(extra, 0, extra.length);
			return o.toByteArray();
		}
	}
}
