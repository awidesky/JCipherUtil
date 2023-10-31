package io.github.awidesky.jCipherUtil.util.cipherEngine;

import java.io.ByteArrayOutputStream;
import java.util.Optional;
import java.util.function.Function;

import javax.crypto.Cipher;

import io.github.awidesky.jCipherUtil.CipherUtil.CipherMode;
import io.github.awidesky.jCipherUtil.messageInterface.OutPut;

public class CipherEncryptEngine extends CipherEngine {

	private byte[] metadata = null;
	private Function<OutPut, Cipher> init;

	public CipherEncryptEngine(CipherMode mode, Function<OutPut, Cipher> init) {
		super(mode);
		this.init = init;
		init();
	}
	
	@Override
	public void init() {
		ByteArrayOutputStream o = new ByteArrayOutputStream();
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
