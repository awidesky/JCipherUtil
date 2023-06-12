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
import static org.junit.jupiter.api.DynamicContainer.dynamicContainer;
import static org.junit.jupiter.api.DynamicTest.dynamicTest;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.channels.FileChannel;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.StandardOpenOption;
import java.security.DigestException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collection;
import java.util.HexFormat;
import java.util.List;
import java.util.stream.Stream;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.DynamicContainer;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.TestFactory;

import io.github.awidesky.jCipher.aes.AESGCMCipherUtil;
import io.github.awidesky.jCipher.messageInterface.MessageConsumer;
import io.github.awidesky.jCipher.messageInterface.MessageProvider;

@DisplayName("Cipher Tests")
class Test {

	static final int CIPHERUTILBUFFERSIZE = 4 * 1024;
	static final CipherUtil[] ciphers = new CipherUtil[] { new AESGCMCipherUtil(CIPHERUTILBUFFERSIZE) };

	static final Charset TESTCHARSET = Charset.forName("UTF-16"); 
	static final SecureRandom ran = new SecureRandom();
	
	static final byte[] src = new byte[64 * 1024];
	static final String randomStr = "random String 1234!@#$";;
	static String srcHash;
	static byte[] encrypted;
	
	static {
		ran.nextBytes(src);
	}
	
	@TestFactory
	@DisplayName("All")
	Collection<DynamicContainer> testALL() throws NoSuchAlgorithmException, DigestException, IOException {
		
		List<DynamicContainer> allTests = new ArrayList<>();

		for (CipherUtil c : ciphers) {
			List<DynamicContainer> singleCipherAlgorithmTests = new ArrayList<>(2);
			Stream<DynamicTest> encryptTests = Stream.of(
					dynamicTest("byte[] -> byte[]", () -> {
						c.init(TestUtil.password);
						assertEquals(TestUtil.hashPlain(src),
								TestUtil.testDecrypt(new ByteArrayInputStream(c.encryptToSingleBuffer(MessageProvider.from(src)))));
					}),	
					dynamicTest("File -> File", () -> {
						c.init(TestUtil.password);
						File fsrc = mkTempPlainFile();
						File fdest = mkEmptyTempFile();
						c.encrypt(MessageProvider.from(fsrc), MessageConsumer.to(fdest));
						assertEquals(TestUtil.hashPlain(new FileInputStream(fsrc)), TestUtil.testDecrypt(new FileInputStream(fdest)));
					}),
					dynamicTest("Base64 encoded String -> Base64 encoded String", () -> {
						c.init(TestUtil.password);
						String result = c.encryptToBase64(MessageProvider.fromBase64(Base64.getEncoder().encodeToString(src)));
						assertEquals(TestUtil.hashPlain(src), TestUtil.testDecrypt(new ByteArrayInputStream(Base64.getDecoder().decode(result))));
					}),
					dynamicTest("Hex encoded String -> Hex encoded String", () -> {
						c.init(TestUtil.password);
						String result = c.encryptToHexString(MessageProvider.fromHexString(HexFormat.of().formatHex(src)));
						assertEquals(TestUtil.hashPlain(src), TestUtil.testDecrypt(new ByteArrayInputStream(HexFormat.of().parseHex(result))));
					}),
					dynamicTest("String -> byte[]", () -> {
						c.init(TestUtil.password);
						assertEquals(TestUtil.hashPlain(randomStr.getBytes(TESTCHARSET)), TestUtil.testDecrypt(
								new ByteArrayInputStream(c.encryptToSingleBuffer(MessageProvider.from(randomStr, TESTCHARSET)))));
					}),
					dynamicTest("Inputstream -> Outputstream", () -> {
						c.init(TestUtil.password);
						File fsrc = mkTempPlainFile();
						File fdest = mkEmptyTempFile();
						c.encrypt(MessageProvider.from(new BufferedInputStream(new FileInputStream(fsrc))),
								MessageConsumer.to(new BufferedOutputStream(new FileOutputStream(fdest))));
						assertEquals(TestUtil.hashPlain(new FileInputStream(fsrc)), TestUtil.testDecrypt(new FileInputStream(fdest)));
					}),
					dynamicTest("part of InputStream -> byte[]", () -> {
						c.init(TestUtil.password);
						File fsrc = mkTempPlainFile();
						assertEquals(TestUtil.hashPlain(new FileInputStream(fsrc), 16 * 1024),
								TestUtil.testDecrypt(new ByteArrayInputStream(c.encryptToSingleBuffer(
										MessageProvider.from(new BufferedInputStream(new FileInputStream(fsrc)), 16 * 1024)))));
					}),
					dynamicTest("ReadableByteChannel -> WritableByteChannel", () -> {
						c.init(TestUtil.password);
						File fsrc = mkTempPlainFile();
						File fdest = mkEmptyTempFile();
						c.encrypt(MessageProvider.from(FileChannel.open(fsrc.toPath(), StandardOpenOption.READ)),
								MessageConsumer.to(FileChannel.open(fdest.toPath(), StandardOpenOption.WRITE)));
						assertEquals(TestUtil.hashPlain(new FileInputStream(fsrc)),
								TestUtil.testDecrypt(new FileInputStream(fdest)));
					}),
					dynamicTest("From part of ReadableByteChannel", () -> {
						c.init(TestUtil.password);
						File fsrc = mkTempPlainFile();
						assertEquals(TestUtil.hashPlain(new FileInputStream(fsrc), 16 * 1024),
								TestUtil.testDecrypt(new ByteArrayInputStream(
										c.encryptToSingleBuffer(MessageProvider.from(FileChannel.open(fsrc.toPath(), StandardOpenOption.READ), 16 * 1024)))));
					})
				);

			c.init(TestUtil.password);
			encrypted = c.encryptToSingleBuffer(MessageProvider.from(src));
			srcHash = TestUtil.hashPlain(src);
			Stream<DynamicTest> decryptTests = Stream.of(
					dynamicTest("byte[] -> byte[]", () -> {
						c.init(TestUtil.password);
						assertEquals(srcHash, TestUtil.hashPlain(c.decryptToSingleBuffer(MessageProvider.from(encrypted))));
					}),
					dynamicTest("File -> File", () -> {
						c.init(TestUtil.password);
						File fsrc = mkTempEncryptedFile();
						File fdest = mkEmptyTempFile();
						c.decrypt(MessageProvider.from(fsrc), MessageConsumer.to(fdest));
						assertEquals(srcHash, TestUtil.hashPlain(new FileInputStream(fdest)));
					}),
					dynamicTest("Base64 encoded String -> Base64 encoded String", () -> {
						c.init(TestUtil.password);
						String result = c.decryptToBase64(MessageProvider.fromBase64(Base64.getEncoder().encodeToString(encrypted)));
						assertEquals(srcHash, TestUtil.hashPlain(Base64.getDecoder().decode(result)));
					}),
					dynamicTest("Hex encoded String -> Hex encoded String", () -> {
						c.init(TestUtil.password);
						String result = c.decryptToHexString(MessageProvider.fromHexString(HexFormat.of().formatHex(encrypted)));
						assertEquals(srcHash, TestUtil.hashPlain(HexFormat.of().parseHex(result)));
					}),
					dynamicTest("Inputstream -> Outputstream", () -> {
						c.init(TestUtil.password);
						File fsrc = mkTempEncryptedFile();
						File fdest = mkEmptyTempFile();
						c.decrypt(MessageProvider.from(new BufferedInputStream(new FileInputStream(fsrc))),
								MessageConsumer.to(new BufferedOutputStream(new FileOutputStream(fdest))));
						assertEquals(srcHash, TestUtil.hashPlain(new FileInputStream(fdest)));
					}),
					dynamicTest("ReadableByteChannel -> WritableByteChannel", () -> {
						c.init(TestUtil.password);
						File fsrc = mkTempEncryptedFile();
						File fdest = mkEmptyTempFile();
						c.decrypt(MessageProvider.from(FileChannel.open(fsrc.toPath(), StandardOpenOption.READ)),
								MessageConsumer.to(FileChannel.open(fdest.toPath(), StandardOpenOption.WRITE)));
						assertEquals(srcHash, TestUtil.hashPlain(new FileInputStream(fdest)));
					})
				);
			
			
			
			singleCipherAlgorithmTests.add(dynamicContainer("Encryption", encryptTests));
			singleCipherAlgorithmTests.add(dynamicContainer("Decryption", decryptTests));
			allTests.add(dynamicContainer(c.toString(), singleCipherAlgorithmTests));
		}
		return allTests;
	}
	
	
	private static File mkTempPlainFile() throws IOException {
		return mkTempFile(src);
	}
	
	private static File mkTempEncryptedFile() throws IOException {
		return mkTempFile(encrypted);
	}
	
	private static File mkTempFile(byte[] data) throws IOException {
		File f = Files.createTempFile("AESGCMTestSrc", "bin").toFile();
		//File fsrc = new File(".\\test.bin");
		if(f.exists()) { f.delete(); f.createNewFile(); }
		f.deleteOnExit();
		BufferedOutputStream bo = new BufferedOutputStream(new FileOutputStream(f));
		bo.write(data);
		bo.close();
		return f;
	}
	private static File mkEmptyTempFile() throws IOException {
		File f = Files.createTempFile("AESGCMTestEmpty", "bin").toFile();
		//File fsrc = new File(".\\test.bin");
		if(f.exists()) { f.delete(); f.createNewFile(); }
		f.deleteOnExit();
		return f;
	}
}




/*
	
	@TestFactory
	Stream<DynamicTest> testAESGCM() {
		return Arrays.stream(ciphers).map(null);
	}
	@TestFactory
	Stream<DynamicTest> testAESCBC() {
		return Arrays.stream(ciphers).map(null);
	}

	
	Stream<DynamicTest> generateTests(CipherUtil c) {
		//Tests 클래스를 만들고, c를 받아서 테스트하기
		return null;
	}
*/