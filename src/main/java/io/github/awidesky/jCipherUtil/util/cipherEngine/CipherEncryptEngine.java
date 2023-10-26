package io.github.awidesky.jCipherUtil.util.cipherEngine;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
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
		if(metadata == null) {
			return Optional.ofNullable(c.update(buf, off, len)).orElse(new byte[0]);
		} else {
			ByteArrayOutputStream o = new ByteArrayOutputStream();
			try {
				o.write(metadata);
				metadata = null;
				o.write(Optional.ofNullable(c.update(buf, off, len)).orElse(new byte[0]));
				return o.toByteArray();
			} catch (IOException e) {
				e.printStackTrace();
				return null;
			}
		}
	}
}
