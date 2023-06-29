package io.github.awidesky.jCipher.cipher.asymmetric.rsa;

import io.github.awidesky.jCipher.metadata.KeySize;

public class RSAKeySize extends KeySize {

	public static final RSAKeySize SIZE_2048 = new RSAKeySize(2048);
	public static final RSAKeySize SIZE_4096 = new RSAKeySize(4096);
	public static final RSAKeySize SIZE_8192 = new RSAKeySize(8192);

	public RSAKeySize(int size) { super(size); }

}
