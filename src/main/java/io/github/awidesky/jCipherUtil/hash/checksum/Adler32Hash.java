package io.github.awidesky.jCipherUtil.hash.checksum;

import java.util.zip.Adler32;

/**
 * Adler-32 checksum hash algorithm
 */
public class Adler32Hash extends CheckSumHash {
	public Adler32Hash() { super(new Adler32()); }

	@Override
	public String getName() { return "Adler32"; }
}
