package io.github.awidesky.jCipher;
import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.channels.FileChannel;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.StandardOpenOption;
import java.security.DigestException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.HexFormat;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;
import org.junit.jupiter.api.Nested;

import io.github.awidesky.jCipher.aes.AESGCMCipher;
import io.github.awidesky.jCipher.messageInterface.MessageConsumer;
import io.github.awidesky.jCipher.messageInterface.MessageProvider;


/*
 * Copyright (c) 2023 Eugene Hong
 *
 * This software is distributed under license. Use of this software
 * implies agreement with all terms and conditions of the accompanying
 * software license.
 * Please refer to LICENSE
 * */

@DisplayName("AES GCM")
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class AESGCMTest {

	public static final Charset TESTCHARSET = Charset.forName("UTF-16"); // TODO : param test? 
	static SecureRandom ran = new SecureRandom();
	static AESGCMCipher c = new AESGCMCipher(8 * 1024);
	
	static byte[] src;
	static String randomStr;
	
	@BeforeAll
	static void setupData() {
		src = new byte[64 * 1024];
		randomStr = "random String 1234!@#$";
		ran.nextBytes(src);
	}
	

	@Nested
	@Order(1)
	@DisplayName("Encryption")
	@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
	class Encryption {
		
		@BeforeEach
		void beforeEach() {
			c.init(TestUtil.password);
		}

		@DisplayName("byte[] -> byte[]")
		@Order(1)
		@Test
		void byteArr() throws IllegalBlockSizeException, BadPaddingException, FileNotFoundException, IOException,
				DigestException, NoSuchAlgorithmException {
			assertEquals(TestUtil.hashPlain(src),
					TestUtil.testDecrypt(new ByteArrayInputStream(c.encryptToSingleBuffer(MessageProvider.from(src)))));
		}

		@DisplayName("File -> File")
		@Order(2)
		@Test
		void file() throws IllegalBlockSizeException, BadPaddingException, FileNotFoundException, IOException,
				DigestException, NoSuchAlgorithmException {
			File fsrc = mkTempPlainFile();
			File fdest = mkEmptyTempFile();
			c.encrypt(MessageProvider.from(fsrc), MessageConsumer.to(fdest));
			assertEquals(TestUtil.hashPlain(new FileInputStream(fsrc)), TestUtil.testDecrypt(new FileInputStream(fdest)));
		}

		@DisplayName("Base64 encoded String -> Base64 encoded String ")
		@Order(3)
		@Test
		void base64() throws IllegalBlockSizeException, BadPaddingException, FileNotFoundException, IOException,
				DigestException, NoSuchAlgorithmException {
			String result = c.encryptToBase64(MessageProvider.fromBase64(Base64.getEncoder().encodeToString(src)));
			assertEquals(TestUtil.hashPlain(src), TestUtil.testDecrypt(new ByteArrayInputStream(Base64.getDecoder().decode(result))));
		}

		@DisplayName("Hex encoded String -> Hex encoded String")
		@Order(4)
		@Test
		void hexStr() throws IllegalBlockSizeException, BadPaddingException, FileNotFoundException, IOException,
				DigestException, NoSuchAlgorithmException {
			String result = c.encryptToHexString(MessageProvider.fromHexString(HexFormat.of().formatHex(src)));
			assertEquals(TestUtil.hashPlain(src), TestUtil.testDecrypt(new ByteArrayInputStream(HexFormat.of().parseHex(result))));
		}

		@DisplayName("String -> byte[]")
		@Order(5)
		@Test
		void string() throws IllegalBlockSizeException, BadPaddingException, FileNotFoundException, IOException,
				DigestException, NoSuchAlgorithmException {
			assertEquals(TestUtil.hashPlain(randomStr.getBytes(TESTCHARSET)), TestUtil.testDecrypt(
					new ByteArrayInputStream(c.encryptToSingleBuffer(MessageProvider.from(randomStr, TESTCHARSET)))));
		}

		@DisplayName("Inputstream -> Outputstream")
		@Order(6)
		@Test
		void inputstream() throws IllegalBlockSizeException, BadPaddingException, FileNotFoundException, IOException,
				DigestException, NoSuchAlgorithmException {
			File fsrc = mkTempPlainFile();
			File fdest = mkEmptyTempFile();
			c.encrypt(MessageProvider.from(new BufferedInputStream(new FileInputStream(fsrc))),
					MessageConsumer.to(new BufferedOutputStream(new FileOutputStream(fdest))));
			assertEquals(TestUtil.hashPlain(new FileInputStream(fsrc)), TestUtil.testDecrypt(new FileInputStream(fdest)));
		}

		@DisplayName("part of InputStream -> byte[]")
		@Order(7)
		@Test
		void inputstream_partial() throws IllegalBlockSizeException, BadPaddingException, FileNotFoundException,
				IOException, DigestException, NoSuchAlgorithmException {
			File fsrc = mkTempPlainFile();
			assertEquals(TestUtil.hashPlain(new FileInputStream(fsrc), 16 * 1024),
					TestUtil.testDecrypt(new ByteArrayInputStream(c.encryptToSingleBuffer(
							MessageProvider.from(new BufferedInputStream(new FileInputStream(fsrc)), 16 * 1024)))));
		}

		@DisplayName("ReadableByteChannel -> WritableByteChannel")
		@Order(8)
		@Test
		void channel() throws IllegalBlockSizeException, BadPaddingException, FileNotFoundException, IOException,
				DigestException, NoSuchAlgorithmException {
			File fsrc = mkTempPlainFile();
			File fdest = mkEmptyTempFile();
			c.encrypt(MessageProvider.from(FileChannel.open(fsrc.toPath(), StandardOpenOption.READ)),
					MessageConsumer.to(FileChannel.open(fdest.toPath(), StandardOpenOption.WRITE)));
			assertEquals(TestUtil.hashPlain(new FileInputStream(fsrc)),
					TestUtil.testDecrypt(new FileInputStream(fdest)));
		}

		@DisplayName("From part of ReadableByteChannel")
		@Order(9)
		@Test
		void channel_partial() throws IllegalBlockSizeException, BadPaddingException, FileNotFoundException,
				IOException, DigestException, NoSuchAlgorithmException {
			File fsrc = mkTempPlainFile();
			assertEquals(TestUtil.hashPlain(new FileInputStream(fsrc), 16 * 1024),
					TestUtil.testDecrypt(new ByteArrayInputStream(
							c.encryptToSingleBuffer(MessageProvider.from(FileChannel.open(fsrc.toPath(), StandardOpenOption.READ), 16 * 1024)))));
		}

		static File mkTempPlainFile() throws IOException {
			return mkTempFile(src);
		}
	}

	@Nested
	@Order(2)
	@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
	@DisplayName("Decryption")
	class Decryption {
		
		static String srcHash;
		static byte[] encrypted;
		
		@BeforeAll
		static void setup() throws NoSuchAlgorithmException, DigestException, IOException, IllegalBlockSizeException, BadPaddingException {
			c.init(TestUtil.password);
			encrypted = c.encryptToSingleBuffer(MessageProvider.from(src));
			srcHash = TestUtil.hashPlain(src);
		}
		
		@BeforeEach
		void beforeEach() {
			c.init(TestUtil.password);
		}

		@DisplayName("byte[] -> byte[]")
		@Order(1)
		@Test
		void byteArr() throws IllegalBlockSizeException, BadPaddingException, FileNotFoundException, IOException,
				DigestException, NoSuchAlgorithmException {
			assertEquals(srcHash, TestUtil.hashPlain(c.decryptToSingleBuffer(MessageProvider.from(encrypted))));
		}

		@DisplayName("File -> File")
		@Order(2)
		@Test
		void file() throws IllegalBlockSizeException, BadPaddingException, FileNotFoundException, IOException,
				DigestException, NoSuchAlgorithmException {
			File fsrc = mkTempEncryptedFile();
			File fdest = mkEmptyTempFile();
			c.decrypt(MessageProvider.from(fsrc), MessageConsumer.to(fdest));
			assertEquals(srcHash, TestUtil.hashPlain(new FileInputStream(fdest)));
		}

		@DisplayName("Base64 encoded String -> Base64 encoded String ")
		@Order(3)
		@Test
		void base64() throws IllegalBlockSizeException, BadPaddingException, FileNotFoundException, IOException,
				DigestException, NoSuchAlgorithmException {
			String result = c.decryptToBase64(MessageProvider.fromBase64(Base64.getEncoder().encodeToString(encrypted)));
			assertEquals(srcHash, TestUtil.hashPlain(Base64.getDecoder().decode(result)));
		}

		@DisplayName("Hex encoded String -> Hex encoded String")
		@Order(4)
		@Test
		void hexStr() throws IllegalBlockSizeException, BadPaddingException, FileNotFoundException, IOException,
				DigestException, NoSuchAlgorithmException {
			String result = c.decryptToHexString(MessageProvider.fromHexString(HexFormat.of().formatHex(encrypted)));
			assertEquals(srcHash, TestUtil.hashPlain(HexFormat.of().parseHex(result)));
		}

		@DisplayName("Inputstream -> Outputstream")
		@Order(5)
		@Test
		void inputstream() throws IllegalBlockSizeException, BadPaddingException, FileNotFoundException, IOException,
				DigestException, NoSuchAlgorithmException {
			File fsrc = mkTempEncryptedFile();
			File fdest = mkEmptyTempFile();
			c.decrypt(MessageProvider.from(new BufferedInputStream(new FileInputStream(fsrc))),
					MessageConsumer.to(new BufferedOutputStream(new FileOutputStream(fdest))));
			assertEquals(srcHash, TestUtil.hashPlain(new FileInputStream(fdest)));
		}

		@DisplayName("ReadableByteChannel -> WritableByteChannel")
		@Order(6)
		@Test
		void channel() throws IllegalBlockSizeException, BadPaddingException, FileNotFoundException, IOException,
				DigestException, NoSuchAlgorithmException {
			File fsrc = mkTempEncryptedFile();
			File fdest = mkEmptyTempFile();
			c.decrypt(MessageProvider.from(FileChannel.open(fsrc.toPath(), StandardOpenOption.READ)),
					MessageConsumer.to(FileChannel.open(fdest.toPath(), StandardOpenOption.WRITE)));
			assertEquals(srcHash, TestUtil.hashPlain(new FileInputStream(fdest)));
		}

		static File mkTempEncryptedFile() throws IOException {
			return mkTempFile(encrypted);
		}
	}
	

	public static File mkTempFile(byte[] data) throws IOException {
		File f = Files.createTempFile("AESGCMTestSrc", "bin").toFile();
		//File fsrc = new File(".\\test.bin");
		if(f.exists()) { f.delete(); f.createNewFile(); }
		f.deleteOnExit();
		BufferedOutputStream bo = new BufferedOutputStream(new FileOutputStream(f));
		bo.write(data);
		bo.close();
		return f;
	}
	public static File mkEmptyTempFile() throws IOException {
		File f = Files.createTempFile("AESGCMTestEmpty", "bin").toFile();
		//File fsrc = new File(".\\test.bin");
		if(f.exists()) { f.delete(); f.createNewFile(); }
		f.deleteOnExit();
		return f;
	}
	
}
