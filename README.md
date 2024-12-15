# JCipherUtil

Java library that provides a simple and universial way to encrypt/decrypt between various sources like Streams, Files...etc.  

JCipherUtil takes all the dirty work you've been doing with Java Cryptography Extension(JCE). 

* It generates safe key with hash iteration with any SHA algorithm you want.
* It saves/loads password iteration count, salt and IV under the hood.

You can just pick a cipher/hash algorithm to use, and way to go!

Most of the modern algorithms(AES/ChaCha/RSA/ECDH/XDH/SHA) are supported.
For detail, please obtain the javadoc from [releases](https://github.com/awidesky/JCipherUtil/releases).(I spent TONs of time writting it)



* [Examples](#examples)  
  
  - [Initialization](#initialization)  
    * [Password as the key](#password-as-the-key)
    * [byte array as the key](#byte-array-as-the-key)
  - [Encrypt/Decrypt with various forms of data](#encrypt-decrypt-with-various-forms-of-data)
    * [byte array](#byte-byte)  
    * [File](#file-file)  
    * [Base64 String](#base64-encoded-string-base64-encoded-string)  
    * [Hex String](#hex-encoded-string-hex-encoded-string)  
    * [Stream](#inputstream-outputstream)  
    * [Channel](#readablebytechannel-writablebytechannel)  
  - [Utility classes](#utility-classes)
    * [CipherTunnel](#ciphertunnel)
    * [CipherEngine](#cipherengine)

* [Installation](#installation)

# Examples

## Initialization

```
char[] password = "tH!s1Smyp@Ssw0rd".toCharArray();
new AES_GCMCipherUtil.Builder(AESKeySize.SIZE_256)
                    .bufferSize(BUFFERSIZE)
                    .keySize(AESKeySize.SIZE_128) // override key size
                    .keyMetadata(KeyMetadata.DEFAULT)
                    .build(password);
                  //.build(byteArray)
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
new SecureRandom().nextBytes(key);
new AES_GCMCipherUtil.Builder(AESKeySize.SIZE_256).build(key);
```

## Encrypt/Decrypt with various forms of data

For example, here's a `CipherUtil`  initialized.

```
CipherUtil cipher = new AES_GCMCipherUtil.Builder(AESKeySize.SIZE_256).build("tH!s1Smyp@Ssw0rd".toCharArray());
```

### byte[] <-> byte[]

```
byte[] src = some_byte_to_encrypt();
byte[] encrypted = cipher.encryptToSingleBuffer(MessageProvider.from(src))
byte[] decrypted = cipher.decryptToSingleBuffer(MessageProvider.from(encrypted));
```

### File <-> File

```
File fsrc = some_file_to_encrypt();
File encDest = destination_of_encrypted_file();
File decDest = destination_of_decrypted_file();
cipher.encrypt( /** Encrypts the file */
    MessageProvider.from(fsrc),
    MessageConsumer.to(encDest)
);
cipher.decrypt( /** Decrypts the file */
    MessageProvider.from(encDest),
    MessageConsumer.to(decDest)
);
```

### Base64 encoded String <-> Base64 encoded String

```
byte[] src = some_byte_to_encrypt();
String str = Base64.getEncoder().encodeToString(src);

String encrypted = cipher.encryptToBase64(MessageProvider.fromBase64(str));
String decrypted = cipher.decryptToBase64(MessageProvider.fromBase64(encrypted));
```

### Hex encoded String <-> Hex encoded String

```
byte[] src = some_byte_to_encrypt();
String str = HexFormat.of().formatHex(src);

String encrypted = cipher.encryptToHexString(MessageProvider.fromHexString(str));
String decrypted = cipher.decryptToHexString(MessageProvider.fromHexString(encrypted));
```

### Plain String <-> Plain String

```
String str = "random String 1234!@#$";
byte[] encrypted = cipher.encryptToSingleBuffer(MessageProvider.from(randomStr, Charset.forName("UTF-16")));
String decrypted = cipher.decryptToString(MessageProvider.from(encrypted), Charset.forName("UTF-16"));
```

### Inputstream <-> Outputstream

```
InputStream src = source_of_data(); // Encrypted or plain
OutputStream dest = dest_of_data(); // Plain or encrypted
cipher.encrypt( /** or decrypt */
    MessageProvider.from(src),
    MessageConsumer.to(dest)
);
```

### ReadableByteChannel <-> WritableByteChannel

```
cipher.encrypt(
    MessageProvider.from(FileChannel.open(srcPath, StandardOpenOption.READ)),
    MessageConsumer.to(FileChannel.open(destPath, StandardOpenOption.WRITE))
);
```

## Utility classes

Utility classes for easier use.

### CipherTunnel

This class is designed to use in situations where blocking-until-entirely-finished methods
(like CipherUtil.encrypt(InPut, OutPut) and CipherUtil.decrypt(InPut, OutPut) should be avoided,
allowing current thread to do other things or check the progress (how much data has been processed, etc.)
in the middle of cipher process.

```
byte[] src = data_to_encrypt();
ByteArrayOutputStream enc = new ByteArrayOutputStream(); //Encrypted data to be stored
int cnt;

CipherTunnel ct = cipher.cipherEncryptTunnel(MessageProvider.from(src), MessageConsumer.to(enc));
cnt = ct.transfer(); // CipherUtil.BUFFER_SIZE bytes are processed.
System.out.println(cnt + "bytes are processed!");
ct.transferFinal(); // process all bytes till the end.

ByteArrayOutputStream dec = new ByteArrayOutputStream(); //Decrypted data
ct = cipher.cipherDecryptTunnel(MessageProvider.from(enc.toByteArray()), MessageConsumer.to(dec));
ct.transferFinal();
assertEquals(Hash.hashPlain(src), Hash.hashPlain(dec.toByteArray())); //true
```

### CipherEngine

CipherEngine is a basically a wrapper of javax.crypto.Cipher that takes care of 
metadata reading/generating, and inner buffering.
update() method encrypts/decrypts given data, and doFinal() finishes the cipher process.

```
byte[] src = some_byte_to_encrypt();
ByteArrayOutputStream dec = new ByteArrayOutputStream();
CipherEngine ue = cipher.cipherEngine(CipherMode.ENCRYPT_MODE);
CipherEngine ud = cipher.cipherEngine(CipherMode.DECRYPT_MODE);

dec.write(ud.update(ue.update(new byte[0]))); //zero array input, does not change cipher process 
/**
 * ue.update() returns encrypted data.
 * Decrypt it with ud.update() and store the decrypted result to dec.
 */
dec.write(ud.update(ue.update(src)));
dec.write(ud.update(ue.update(new byte[0]))); //zero array input, does not change cipher process
dec.write(ud.doFinal(ue.doFinal(null))); //finishes the cipher process
assertEquals(src, dec.toByteArray()); // true
```

# Installation

Use maven to set dependency. ([Maven repository](https://mvnrepository.com/artifact/io.github.awidesky/JCipherUtil))

```
<!-- https://mvnrepository.com/artifact/io.github.awidesky/JCipherUtil -->
<dependency>
    <groupId>io.github.awidesky</groupId>
    <artifactId>JCipherUtil</artifactId>
    <version>1.2.0</version>
</dependency>
```