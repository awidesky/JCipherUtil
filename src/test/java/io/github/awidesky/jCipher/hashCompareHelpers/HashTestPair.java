package io.github.awidesky.jCipher.hashCompareHelpers;

import io.github.awidesky.jCipherUtil.hash.Hash;

public interface HashTestPair {

	public Hash getHash();
	public HashComparator getCmp();
}
