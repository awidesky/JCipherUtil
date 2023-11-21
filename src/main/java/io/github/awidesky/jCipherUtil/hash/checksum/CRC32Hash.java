package io.github.awidesky.jCipherUtil.hash.checksum;

import java.util.zip.CRC32;

/**
 * CRC-32 checksum hash algorithm
 */
public class CRC32Hash extends CheckSumHash {
	public CRC32Hash() { super(new CRC32()); }

	@Override
	public String getName() { return "CRC32"; }
}
