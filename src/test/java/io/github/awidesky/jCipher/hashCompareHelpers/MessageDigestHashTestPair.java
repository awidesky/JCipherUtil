package io.github.awidesky.jCipher.hashCompareHelpers;

import java.util.function.Supplier;

import io.github.awidesky.jCipherUtil.hash.messageDigest.MessageDigestHash;

public class MessageDigestHashTestPair implements HashTestPair {
	private final Supplier<MessageDigestHash> hash;
	private final MessageDigestComparator cmp;
	
	public MessageDigestHashTestPair(Supplier<MessageDigestHash> hash) {
		this.hash = hash;
		this.cmp = new MessageDigestComparator(hash.get().getName());
	}
	
	@Override
	public MessageDigestHash getHash() {
		return hash.get();
	}

	@Override
	public MessageDigestComparator getCmp() {
		return cmp;
	}

}
