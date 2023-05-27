package io.github.awidesky.jCipher;
import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.channels.FileChannel;
import java.nio.channels.ReadableByteChannel;
import java.nio.channels.WritableByteChannel;
import java.nio.file.Files;
import java.nio.file.StandardOpenOption;
import java.security.DigestException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.HexFormat;
import java.util.stream.Stream;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import io.github.awidesky.jCipher.aes.AESGCMCipher;
import io.github.awidesky.jCipher.dataIO.MessageConsumer;
import io.github.awidesky.jCipher.dataIO.MessageProvider;

/*
 * Copyright (c) 2023 Eugene Hong
 *
 * This software is distributed under license. Use of this software
 * implies agreement with all terms and conditions of the accompanying
 * software license.
 * Please refer to LICENSE
 * */

@DisplayName("AESGCMTest")
class AESGCMTest {

	static SecureRandom ran = new SecureRandom();
	
	static byte[] src;
	static File fsrc;
	static InputStream isrc;
	static ReadableByteChannel chsrc;
	
	static String randomStr = "random String 1234!@#$";
	static char[] password = "tH!s1Smyp@Ssw0rd".toCharArray();
	
	static File fdest;
	static OutputStream idest;
	static WritableByteChannel chdest;
	
	@BeforeEach
	void setup() throws IOException {
		src = new byte[64 * 1024];
		ran.nextBytes(src);
		fsrc = Files.createTempFile("AESGCMTest", "bin").toFile();
		fsrc.deleteOnExit();
		isrc = new BufferedInputStream(new FileInputStream(fsrc));
		chsrc = FileChannel.open(fsrc.toPath(), StandardOpenOption.READ);
		{
			BufferedOutputStream bo = new BufferedOutputStream(new FileOutputStream(fsrc));
			byte[] a = new byte[8 * 1024];
			for (int i = 0; i < 8; i++) {
				ran.nextBytes(a);
				bo.write(a);
			}
			bo.close();
		}
		
		fdest = Files.createTempFile("AESGCMTest", "bin").toFile();
		idest = new BufferedOutputStream(new FileOutputStream(fdest));
		chdest = FileChannel.open(fdest.toPath(), StandardOpenOption.WRITE);
	}
	
	
	@ParameterizedTest
	@MethodSource("AESGCMTest#generaltoProvider")
	void file(MessageConsumer to)
			throws IllegalBlockSizeException, BadPaddingException, FileNotFoundException, IOException, DigestException, NoSuchAlgorithmException {
		AESGCMCipher c = new AESGCMCipher(16 * 1024);
		c.init(password);
		c.encrypt(MessageProvider.from(fsrc), to);
		
		//TODO : assertEquals(testEncrypt(new FileInputStream(fsrc)), hashPlain(new FileInputStream(fdest)));
	}
	
	
	static Stream<CipherUtil> AESProvider() {
		return Stream.of(new AESGCMCipher(ran.nextInt(1024, 64 * 1024)));
	}
	//, MessageProvider.from(randomStr), MessageProvider.from(null, null)
	static Stream<MessageProvider> generalFromProvider() throws FileNotFoundException {
		return Stream.of(MessageProvider.from(src), MessageProvider.from(fsrc), MessageProvider.from(isrc), MessageProvider.from(chsrc));
	}
	static Stream<MessageConsumer> generaltoProvider() throws FileNotFoundException {
		return Stream.of(MessageConsumer.to(fdest), MessageConsumer.to(idest), MessageConsumer.to(chdest));
	}

	static String hashPlain(InputStream is) throws NoSuchAlgorithmException, IOException, DigestException {
		MessageDigest digest = MessageDigest.getInstance("SHA-512");
		int read = 0;
		byte[] buf = new byte[8 * 1024];
		while((read = is.read(buf)) != -1) digest.digest(buf, 0, read);
		
		return HexFormat.of().formatHex(digest.digest());
	}
	static String testDecrypt(InputStream is) throws DigestException, IOException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException {
		MessageDigest digest = MessageDigest.getInstance("SHA-512");
		digest.reset();
		new AESGCMCipher(8 * 1024).decrypt(MessageProvider.from(is), digest::digest);
		return HexFormat.of().formatHex(digest.digest());
	}
	static String testEncrypt(InputStream is) throws DigestException, IOException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException {
		MessageDigest digest = MessageDigest.getInstance("SHA-512");
		digest.reset();
		new AESGCMCipher(8 * 1024).encrypt(MessageProvider.from(is), digest::digest);
		return HexFormat.of().formatHex(digest.digest());
	}
	
}
