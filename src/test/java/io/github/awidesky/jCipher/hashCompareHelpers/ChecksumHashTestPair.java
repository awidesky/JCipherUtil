package io.github.awidesky.jCipher.hashCompareHelpers;

import java.util.function.Supplier;
import java.util.zip.Checksum;

import io.github.awidesky.jCipherUtil.hash.checksum.CheckSumHash;

public class ChecksumHashTestPair implements HashTestPair {
	
	private final Supplier<CheckSumHash> hash;
	private final ChecksumComparator cmp;
	
	public ChecksumHashTestPair(Supplier<CheckSumHash> hash, Checksum cs) {
		this.hash = hash;
		this.cmp = new ChecksumComparator(cs);
	}

	@Override
	public CheckSumHash getHash() {
		return hash.get();
	}

	@Override
	public ChecksumComparator getCmp() {
		return cmp;
	}

}
