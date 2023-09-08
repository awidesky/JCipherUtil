package io.github.awidesky.jCipherUtil.key;

import java.util.Random;

import javax.security.auth.Destroyable;

public abstract class KeyMaterial implements Destroyable {

	@Override
	public abstract void destroy();
	@Override
	public abstract boolean isDestroyed();

	/**
	 * clear a given byte array to random data.
	 * @param arr array to clear
	 */
	protected void clearArray(byte[] arr) {
		Random r = new Random();
		for(int i = 0; i < arr.length; i++) {
			arr[i] = (byte)r.nextInt();
		}
	}
}
