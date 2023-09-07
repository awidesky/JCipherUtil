package io.github.awidesky.jCipherUtil.cipher.asymmetric.rsa;

import io.github.awidesky.jCipherUtil.key.KeySize;

/**
 * Denotes RSA key size in bits.
 */
public class RSAKeySize extends KeySize {

	public static final RSAKeySize SIZE_512 = new RSAKeySize(512);
	public static final RSAKeySize SIZE_1024 = new RSAKeySize(1024);
	public static final RSAKeySize SIZE_2048 = new RSAKeySize(2048);
	public static final RSAKeySize SIZE_4096 = new RSAKeySize(4096);
	public static final RSAKeySize SIZE_8192 = new RSAKeySize(8192);

	/** Create custom RSA key size. */
	public RSAKeySize(int size) { super(size); }

}
