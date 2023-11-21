package io.github.awidesky.jCipher.hashCompareHelpers;

import java.nio.ByteBuffer;
import java.util.zip.Checksum;

public class ChecksumComparator implements HashComparator {
	private final Checksum cs;
	
	public ChecksumComparator(Checksum c) { cs = c; }
	
	@Override
	public byte[] hash(byte[] buf) {
		cs.reset();
		cs.update(buf);
		return ByteBuffer.allocate(Long.BYTES).putLong(cs.getValue()).array();
	}
	
	public long hashLong(byte[] buf) {
		cs.reset();
		cs.update(buf);
		return cs.getValue();
	}
}
