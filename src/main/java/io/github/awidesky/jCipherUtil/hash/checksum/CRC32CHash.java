package io.github.awidesky.jCipherUtil.hash.checksum;

import java.util.zip.CRC32C;

/**
 * CRC-32C checksum hash algorithm
 */
public class CRC32CHash extends CheckSumHash {
	public CRC32CHash() { super(new CRC32C()); }

	@Override
	public String getName() { return "CRC32C"; }
}
