# JCipherUtil
Simple Java library that provides a wrapper to encrypt between various sources like Streams, Files...etc.  
  
* [Examples](#examples)  
	* [Initialization](#initialization)  
    	* [byte array Encryption/Decryption](#byte-byte)  



# Examples  

## Initialization    
```
char[] password = "tH!s1Smyp@Ssw0rd".toCharArray();
new AES_GCMCipherUtil.Builder(AESKeySize.SIZE_256)
					.bufferSize(BUFFERSIZE)
					.keySize(AESKeySize.SIZE_128) // override key size
					.keyMetadata(KeyMetadata.DEFAULT)
					.build(password);
				  //.built(byteArray)
```
### Password as the key
```
char[] password = "tH!s1Smyp@Ssw0rd".toCharArray();
new AES_GCMCipherUtil.Builder(AESKeySize.SIZE_256).build(password);
```
### byte array as the key
```
byte[] key = new byte[some_random_size]; //size of the key is irrelevant
// there are no required format or length for the key.
// the array will be hashed and stretched(if needed) to match required key size.
// even though, long and random data is recommended.
new Random().nextBytes(key);
new AES_GCMCipherUtil.Builder(AESKeySize.SIZE_256).build(key);
```
## CipherTunnel  
```
ByteArrayOutputStream enc = new ByteArrayOutputStream();
ByteArrayOutputStream dec = new ByteArrayOutputStream();
CipherTunnel ct = cipher.cipherEncryptTunnel(MessageProvider.from(src), MessageConsumer.to(enc));
ct.transfer();
ct.transfer();
ct.transferFinal();
ct = cipher.cipherDecryptTunnel(MessageProvider.from(enc.toByteArray()), MessageConsumer.to(dec));
ct.transfer();
ct.transfer();
ct.transferFinal();
assertEquals(Hash.hashPlain(src), Hash.hashPlain(dec.toByteArray()));
```
## Updatable encrypter/decrypter
```
					ByteArrayOutputStream enc = new ByteArrayOutputStream();
					ByteArrayOutputStream dec = new ByteArrayOutputStream();
					UpdatableEncrypter ue = cipher.UpdatableEncryptCipher(MessageConsumer.to(enc));
					ue.update(src);
					ue.doFinal(null);
					UpdatableDecrypter ud = cipher.UpdatableDecryptCipher(MessageProvider.from(enc.toByteArray()));
					dec.write(ud.update());
					dec.write(ud.doFinal());
					assertEquals(Hash.hashPlain(src), Hash.hashPlain(dec.toByteArray()));
```
## byte[] <-> byte[]
```
cipher.decryptToSingleBuffer(MessageProvider.from(cipher.encryptToSingleBuffer(MessageProvider.from(src))))));
```
				dynamicTest("File <-> File", () -> {
					File fsrc = mkTempPlainFile();
					File encDest = mkEmptyTempFile();
					File decDest = mkEmptyTempFile();
					cipher.encrypt(MessageProvider.from(fsrc), MessageConsumer.to(encDest));
					cipher.decrypt(MessageProvider.from(encDest), MessageConsumer.to(decDest));
					assertEquals(Hash.hashPlain(new FileInputStream(fsrc)), Hash.hashPlain(new FileInputStream(decDest)));
				}),
				dynamicTest("Base64 encoded String <-> Base64 encoded String", () -> {
					String encrypted = cipher.encryptToBase64(MessageProvider.fromBase64(Base64.getEncoder().encodeToString(src)));
					String decrypted = cipher.decryptToBase64(MessageProvider.fromBase64(encrypted));
					assertEquals(Base64.getEncoder().encodeToString(src), decrypted);
				}),
				dynamicTest("Hex encoded String <-> Hex encoded String", () -> {
					String encrypted = cipher.encryptToHexString(MessageProvider.fromHexString(HexFormat.of().formatHex(src)));
					String decrypted = cipher.decryptToHexString(MessageProvider.fromHexString(encrypted));
					assertEquals(HexFormat.of().formatHex(src), decrypted);
				}),
				dynamicTest("String <-> String", () -> {
					assertEquals(randomStr, cipher.decryptToString(MessageProvider.from(
							cipher.encryptToSingleBuffer(MessageProvider.from(randomStr, TESTCHARSET))), TESTCHARSET));
				}),
				dynamicTest("Inputstream <-> Outputstream", () -> {
					File fsrc = mkTempPlainFile();
					File encDest = mkEmptyTempFile();
					File decDest = mkEmptyTempFile();
					cipher.encrypt(MessageProvider.from(new BufferedInputStream(new FileInputStream(fsrc))),
							MessageConsumer.to(new BufferedOutputStream(new FileOutputStream(encDest))));
					cipher.decrypt(MessageProvider.from(new BufferedInputStream(new FileInputStream(encDest))),
							MessageConsumer.to(new BufferedOutputStream(new FileOutputStream(decDest))));
					assertEquals(Hash.hashPlain(new FileInputStream(fsrc)), Hash.hashPlain(new FileInputStream(decDest)));
				}),
				dynamicTest("From part of InputStream", () -> {
					File fsrc = mkTempPlainFile();
					assertEquals(Hash.hashPlain(new FileInputStream(fsrc), 71),
							Hash.hashPlain(cipher.decryptToSingleBuffer(MessageProvider.from(cipher.encryptToSingleBuffer(
									MessageProvider.from(new BufferedInputStream(new FileInputStream(fsrc)), 71))))));
				}),
				dynamicTest("ReadableByteChannel <-> WritableByteChannel", () -> {
					File fsrc = mkTempPlainFile();
					File encDest = mkEmptyTempFile();
					File decDest = mkEmptyTempFile();
					cipher.encrypt(MessageProvider.from(FileChannel.open(fsrc.toPath(), StandardOpenOption.READ)),
							MessageConsumer.to(FileChannel.open(encDest.toPath(), StandardOpenOption.WRITE)));
					cipher.decrypt(MessageProvider.from(FileChannel.open(encDest.toPath(), StandardOpenOption.READ)),
							MessageConsumer.to(FileChannel.open(decDest.toPath(), StandardOpenOption.WRITE)));
					assertEquals(Hash.hashPlain(new FileInputStream(fsrc)), Hash.hashPlain(new FileInputStream(decDest)));
				}),
				dynamicTest("From part of ReadableByteChannel", () -> {
					File fsrc = mkTempPlainFile();
					assertEquals(Hash.hashPlain(new FileInputStream(fsrc), 71),
							Hash.hashPlain(cipher.decryptToSingleBuffer(MessageProvider.from(new ByteArrayInputStream(
									cipher.encryptToSingleBuffer(MessageProvider.from(FileChannel.open(fsrc.toPath(), StandardOpenOption.READ), 71)))))));
				})

# Installation
asdfasdf