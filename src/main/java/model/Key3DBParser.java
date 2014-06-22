package model;

import java.io.File;
import java.io.IOException;
import java.security.DigestException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.DESedeKeySpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.log4j.Logger;


public class Key3DBParser {
	private final static Logger logger = Logger.getLogger(Key3DBParser.class);

	private static final byte[] VERSION_STR = "Version".getBytes();
	private static final byte[] GLOBAL_SALT_STR = "global-salt".getBytes();
	private static final String PASSWORD_CHECK_STR = "password-check";
	private static final byte[] PASSWORD_CHECK_BYTES = PASSWORD_CHECK_STR.getBytes();
	
	public static String NEWLINE = System.getProperty("line.separator");

	@SuppressWarnings("unused")
	// TODO use for decrypting signons.sqlite // TODO remove ?
	private static final byte[] DEFAULT_SIGNONS_PASSWORD = Key3DBParser.convertHextoByte("f8000000000000000000000000000001");
	private static final int ENC_PASSWORD_CHECK_LENGTH = 16;
	private static final int GLOBAL_KEY_LENGTH = 20;

	
	private final byte[] key3Bytes;
	private byte[] globalSalt;
	private Integer globalSaltIndex;
	private byte[] encPasswordCheck;
	private byte[] entrySalt;

	public Key3DBParser(String key3Path) throws IOException, NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException {
		key3Bytes = FileIO.getBytesFromFile(new File(key3Path));
	}
	
	public String parse() throws Key3DBParseException {
		StringBuilder b = new StringBuilder();
		String tmp;
		if( (tmp = parseVersion()) == null )
			throw new Key3DBParseException("Can't parse version.");			
		b.append("Version: " + tmp + NEWLINE);
		if( (tmp = parseGlobalSalt()) == null )
			throw new Key3DBParseException("Can't parse global salt.");
		b.append("Global salt: " + tmp + NEWLINE);
		if( (tmp = parseEntrySalt()) == null )
			throw new Key3DBParseException("Can't parse entry salt.");
		b.append("Entry salt: " + tmp + NEWLINE);
		if( (tmp = parseEncryptedPasswordCheck()) == null )
			throw new Key3DBParseException("Can't parse global salt.");
		b.append("Encrypted PasswordCheck: " + tmp + NEWLINE);
		return b.toString();
	}	
	
	public byte[] getEntrySalt() {
		return entrySalt;
	}
	public byte[] getGlobalSalt() {
		return globalSalt;
	}
	public byte[] getEncPasswordCheck() {
		return encPasswordCheck;
	}
	
	private String parseVersion() {
		Integer index = indexOf(VERSION_STR, key3Bytes);
		if (index != null) {
			return String.valueOf(key3Bytes[index - 1]);
		}
		return null;
	}

	private String parseEncryptedPasswordCheck() {
		Integer index = indexOf(PASSWORD_CHECK_BYTES, key3Bytes);
		if (index != null) {
			int from = index - ENC_PASSWORD_CHECK_LENGTH;
			int to = index;
			encPasswordCheck = Arrays.copyOfRange(key3Bytes, from, to);
			return convertByteToHex(encPasswordCheck);
		}
		return null;
	}

	private String parseEntrySalt() {
		if (globalSaltIndex != null) {
			int saltLength = key3Bytes[globalSaltIndex + GLOBAL_SALT_STR.length
					+ 1];
			logger.debug("Salt length: " + saltLength);
			int from = globalSaltIndex + GLOBAL_SALT_STR.length + 3;
			int to = from + saltLength;
			entrySalt = Arrays.copyOfRange(key3Bytes, from, to);
			return convertByteToHex(entrySalt);
		}
		return null;
	}

	private String parseGlobalSalt() {
		globalSaltIndex = indexOf(GLOBAL_SALT_STR, key3Bytes);
		if (globalSaltIndex != null) {
			int from = globalSaltIndex - GLOBAL_KEY_LENGTH;
			int to = globalSaltIndex;
			globalSalt = Arrays.copyOfRange(key3Bytes, from, to);
			return convertByteToHex(globalSalt);
		}
		return null;
	}
	

// TODO: i just leave the old version in here for some time	
//	public int decryptPasswordCheck_debug(byte[] password, byte[] cryptText) throws InvalidKeyException, InvalidKeySpecException, InvalidAlgorithmParameterException, IllegalBlockSizeException, DigestException, ShortBufferException, IllegalStateException{
//		
////		keyTime -= System.currentTimeMillis();
//		
//		// TODO: 
//		// HP = SHA1(global-salt||password)
//		System.arraycopy(globalSalt, 0, buff_tmp, 0, globalSalt.length);
//		System.arraycopy(password, 0, buff_tmp, globalSalt.length, password.length);
//		md_sha1.update(buff_tmp, 0, globalSalt.length + password.length);
//		//byte[] hp = md_sha1.digest();
//		md_sha1.digest(hp, 0, 20);
//		
//		// CHP = SHA1(HP||ES)
//		System.arraycopy(hp, 0, buff_tmp, 0, hp.length);
//		System.arraycopy(entrySalt, 0, buff_tmp, hp.length, entrySalt.length);
//		md_sha1.update(buff_tmp, 0, hp.length + entrySalt.length);
//		//byte[] chp = md_sha1.digest();
//		md_sha1.digest(chp, 0, 20);
//		
//		// k1 = CHMAC(PES||ES)
//		SecretKeySpec signingKey = new SecretKeySpec(chp, HMAC_SHA1_ALGORITHM);
//		mac.init(signingKey);
//		//System.out.println("mac length " + mac.getMacLength());
//		//byte[] k1 = mac.doFinal(pes_es);
//		mac.update(pes_es);
//		mac.doFinal(k1, 0);
//		
//		// tk = CHMAC(PES)
//		//byte[] tk = mac.doFinal(pes);
//		mac.update(pes);
//		mac.doFinal(tk, 0);
//		
//		// k2 = CHMAC(tk||ES)
//		System.arraycopy(tk, 0, buff_tmp, 0, tk.length);
//		System.arraycopy(entrySalt, 0, buff_tmp, tk.length, entrySalt.length);
//		mac.update(buff_tmp, 0, tk.length + entrySalt.length);
//		//byte[] k2 = mac.doFinal();		
//		mac.doFinal(k2, 0);
//		
//		// k = k1||k2
//		int klen = k1.length + k2.length;
//		System.arraycopy(k1, 0, buff_tmp, 0, k1.length);
//		System.arraycopy(k2, 0, buff_tmp, k1.length, k2.length);
//		// That class only gets the first 24 bytes, so we don't need to care about the buff_tmp length
//		DESedeKeySpec keySpec = new DESedeKeySpec(buff_tmp);
//		SecretKey key = des_secKeyFactory.generateSecret(keySpec);
//		// TODO use pre alocated 8 byte buffer here ?
//		//byte[] desIV = Arrays.copyOfRange(buff_tmp, klen - 8, klen);
//		IvParameterSpec iv = new IvParameterSpec(buff_tmp, klen-8, 8);
//		
//		
////		keyTime += System.currentTimeMillis();
////		decrTime -= System.currentTimeMillis();
//		
//		
//		des_cipher.init(Cipher.DECRYPT_MODE, key, iv);
//		try {
//			//return des_cipher.doFinal(cryptText);
//			int foo = des_cipher.doFinal(cryptText, 0, cryptText.length, buff_tmp);
////			decrTime += System.currentTimeMillis();
//			return foo;
//		} catch (BadPaddingException e) {
////			decrTime += System.currentTimeMillis();
//			return -1;
//		}
//	}	

	private static Integer indexOf(byte[] subarray, byte[] array) {

		if (subarray.length > array.length) {
			return null;
		}

		for (int i = 0; i < array.length; i++) {
			// possible starting index of subarray?
			if (array[i] == subarray[0]) {
				boolean found = true;
				// test all other indices of subarray
				for (int j = 1; j < subarray.length; j++) {
					if (!(array[i + j] == subarray[j])) {
						found = false;
						break;
					}
				}
				// all other values where equal, so return starting index
				if (found) {
					return i;
				}
			}
		}
		return null;
	}

	/**
	 * Helping method to convert a byte array to a hex String
	 * 
	 * @param array
	 * @return
	 */
	private static String convertByteToHex(byte array[]) {
		StringBuilder buffer = new StringBuilder();
		for (int i = 0; i < array.length; i++) {
			if ((array[i] & 0xff) < 0x10) {
				buffer.append("0");
			}
			buffer.append(Integer.toString(array[i] & 0xff, 16) + " ");
		}
		return buffer.toString();
	}

	/**
	 * Helping method to convert a hex String to a byte array
	 * 
	 * @param hexString
	 * @return
	 */
	private static byte[] convertHextoByte(String hexString) {
		char[] hex = hexString.toCharArray();
		byte[] result = new byte[hex.length / 2];
		for (int i = 0; i < result.length; i++) {
			result[i] = (byte) ((Character.digit(hex[i * 2], 16) << 4) + Character
					.digit(hex[i * 2 + 1], 16));
		}
		return result;
	}

//	@SuppressWarnings("unused")
//	private static boolean testDecryption() {
//		byte[] password = Key3DBParser.convertHextoByte("70617373776f7264");
//		byte[] entrySalt = Key3DBParser
//				.convertHextoByte("1596bb8112652a43e7bdfb2fdc8799e5");
//		byte[] globalSalt = Key3DBParser
//				.convertHextoByte("5aac8e0439e8d69ea0fe1bc013cd5af8");
//		byte[] data = Key3DBParser
//				.convertHextoByte("c0846848fe6e3524fdd4a6e3e783cf38");
//		String result = decryptPasswordCheck(password, entrySalt, globalSalt,
//				data);
//		System.out.println("result string: " + result);
//		return result.equals(new String(PASSWORD_CHECK_BYTES));
//	}

}
