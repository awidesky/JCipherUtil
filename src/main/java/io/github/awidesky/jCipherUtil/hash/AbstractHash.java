package io.github.awidesky.jCipherUtil.hash;

public abstract class AbstractHash implements Hash {


	protected abstract void update(byte[] buf);
	protected abstract void doFinal(byte[] buf);
	
}
