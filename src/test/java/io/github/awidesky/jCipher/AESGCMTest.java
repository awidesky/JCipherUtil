/*
 * Copyright (c) 2023 Eugene Hong
 *
 * This software is distributed under license. Use of this software
 * implies agreement with all terms and conditions of the accompanying
 * software license.
 * Please refer to LICENSE
 * */

package io.github.awidesky.jCipher;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

import java.io.BufferedOutputStream;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.security.DigestException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.Random;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import io.github.awidesky.jCipher.aes.AESGCMCipher;
import io.github.awidesky.jCipher.messageInterface.MessageConsumer;
import io.github.awidesky.jCipher.messageInterface.MessageProvider;

@Disabled("this was for temporary use")
class AESGCMTest {

	Random rand = new Random();
	char[] password = "tH!s1Smyp@Ssw0rd".toCharArray();
	
	
	@BeforeEach
	void setUp() throws Exception {

	}

	@Test
	@DisplayName("encrypt/decrypt byte[]")
	void encrypt_byteArr() throws IllegalBlockSizeException, BadPaddingException, IOException, NoSuchAlgorithmException, DigestException {
		byte[] src = new byte[16 * 1024];
		String srcHash;
		String destHash;
		byte[] dest;
		rand.nextBytes(src);
		srcHash = TestUtil.hashPlain(new ByteArrayInputStream(src));
		System.out.println("Encrypt");
		dest = new AESGCMCipher(8 * 1024).init(password).encryptToSingleBuffer(MessageProvider.from(src));
		assertNotEquals(HexFormat.of().formatHex(src), HexFormat.of().formatHex(Arrays.copyOfRange(dest, 80, dest.length)), () -> "Original Message and Encrypted Message should not be the same!");
		
		System.out.println(HexFormat.of().formatHex(src));
		System.out.println(HexFormat.of().formatHex(Arrays.copyOfRange(dest, 80, dest.length)));
		
		System.out.println("Decrypt");
		destHash = TestUtil.hashPlain(new ByteArrayInputStream(new AESGCMCipher(8 * 1024).init(password).decryptToSingleBuffer(MessageProvider.from(dest))));
		assertEquals(srcHash, destHash);
	}
	
	@Test
	@DisplayName("encrypt/decrypt File")
	void encrypt_File() throws IllegalBlockSizeException, BadPaddingException, IOException, NoSuchAlgorithmException, DigestException {
		File src = Files.createTempFile("AESGCMTestSrc", "bin").toFile();
		File dest = Files.createTempFile("AESGCMTestDest", "bin").toFile();
		{
			BufferedOutputStream bo = new BufferedOutputStream(new FileOutputStream(src));
			byte[] a = new byte[8 * 1024];
			for (int i = 0; i < 8; i++) {
				rand.nextBytes(a);
				bo.write(a);
			}
			bo.close();
		}
		
		System.out.println("Encrypt");
		new AESGCMCipher(8 * 1024).init(password).encrypt(MessageProvider.from(src), MessageConsumer.to(dest));
		System.out.println("Decrypt");
		assertEquals(TestUtil.hashPlain(new ByteArrayInputStream(new AESGCMCipher(8 * 1024).init(password).decryptToSingleBuffer(MessageProvider.from(dest)))),
				TestUtil.hashPlain(new ByteArrayInputStream(Files.readAllBytes(dest.toPath()))));
	}
	
}
