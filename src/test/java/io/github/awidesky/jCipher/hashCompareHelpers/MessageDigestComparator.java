package io.github.awidesky.jCipher.hashCompareHelpers;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class MessageDigestComparator implements HashComparator {
	private final MessageDigest md;
	
	public MessageDigestComparator(String name) {
		try {
			this.md = MessageDigest.getInstance(name);
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException(e);
		}
	}
	
	@Override
	public byte[] hash(byte[] buf) {
		md.reset();
		return md.digest(buf);
	}	
}
