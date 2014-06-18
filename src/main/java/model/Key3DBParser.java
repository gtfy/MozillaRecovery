package model;

import java.io.File;
import java.io.IOException;
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
import javax.crypto.spec.DESedeKeySpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.log4j.Logger;


public class Key3DBParser {

	private static final byte[] VERSION_STR = "Version".getBytes();
	private static final byte[] GLOBAL_SALT_STR = "global-salt".getBytes();
	
	
	private static final String PASSWORD_CHECK_STR = "password-check";
	private static final byte[] PASSWORD_CHECK_BYTES = PASSWORD_CHECK_STR.getBytes();
	
	private final static Logger logger = Logger.getLogger(Key3DBParser.class);
	public static String NEWLINE = System.getProperty("line.separator");

	@SuppressWarnings("unused")
	// TODO use for decrypting signons.sqlite
	private static final byte[] DEFAULT_SIGNONS_PASSWORD = Key3DBParser
			.convertHextoByte("f8000000000000000000000000000001");

	private static final int ENC_PASSWORD_CHECK_LENGTH = 16;
	private static final int GLOBAL_KEY_LENGTH = 20;

	
	private final byte[] key3Bytes;
	private byte[] globalSalt;
	private Integer globalSaltIndex;
	private byte[] encPasswordCheck;
	private byte[] entrySalt;


	// Some vars we are going to reuse in the new decryptPasswordCheck functino
	private final MessageDigest md_sha1;
	private final Mac mac = Mac.getInstance(HMAC_SHA1_ALGORITHM);
	private final Cipher des_cipher;
	private final SecretKeyFactory des_secKeyFactory;
	private byte[] pes_es;
	private byte[] pes;
	// We (re)use this buffer for key concatenating and such
	// TODO: 1024 should be enough, but CHECK IT !! 1!!
	private final byte[] buff_tmp = new byte[2048]; 

	
	
	
	public Key3DBParser(String key3Path) throws IOException, NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException {
		key3Bytes = FileIO.getBytesFromFile(new File(key3Path));
		
		md_sha1 = MessageDigest.getInstance(SHA1_ALGORITHM);
		des_cipher = Cipher.getInstance("DESede/CBC/PKCS5Padding", "SunJCE");
		des_secKeyFactory =  SecretKeyFactory.getInstance("DESede");
		
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
			
			// This part isn't going to be changed, so we do it once
			pes = new byte[20];
			System.arraycopy(entrySalt, 0, pes, 0, 20);
			pes_es = new byte[entrySalt.length + 20];			
			System.arraycopy(entrySalt, 0, pes_es, 0, 20);
			System.arraycopy(entrySalt, 0, pes_es, 20, entrySalt.length);
			
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
	
	
	private static final String HMAC_SHA1_ALGORITHM = "HmacSHA1";
	private static final String SHA1_ALGORITHM = "SHA-1";
	public static byte[] sha1Hmac(byte[] data, byte[] key) {
		try {
			SecretKeySpec signingKey = new SecretKeySpec(key,
					HMAC_SHA1_ALGORITHM);
			
			Mac mac = Mac.getInstance(HMAC_SHA1_ALGORITHM);
			
			mac.init(signingKey);
			return mac.doFinal(data);
		} catch (NoSuchAlgorithmException | InvalidKeyException e) {
			e.printStackTrace();
			logger.fatal(e.getMessage());
		} 
		return null;

	}
	
	
	public boolean isMasterpass(byte[] pass) throws InvalidKeyException, InvalidKeySpecException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException{
		return Arrays.equals(decryptPasswordCheck(pass, encPasswordCheck), PASSWORD_CHECK_BYTES);
	}
	
	
	/**
	 * Faster decryptPasswordCheck implementation, due to less object creations and buffer allocations.
	 * 
	 * @param password
	 * @param cryptText
	 * @return decrypted text as byte[] or null if there was some padding error
	 * @throws InvalidKeyException
	 * @throws InvalidKeySpecException
	 * @throws InvalidAlgorithmParameterException
	 * @throws IllegalBlockSizeException
	 * 
	 * TODO:
	 *  - We should be able to reuse almost every byte array and read into them instead of recreating them again and again.
	 *  - If the input buffer for hp is a new buffer, we could save the gs move to the buffer and do it once after the gs is found 
	 */
	public byte[] decryptPasswordCheck(byte[] password, byte[] cryptText) throws InvalidKeyException, InvalidKeySpecException, InvalidAlgorithmParameterException, IllegalBlockSizeException{
		// TODO: 
		// HP = SHA1(global-salt||password)
		System.arraycopy(globalSalt, 0, buff_tmp, 0, globalSalt.length);
		System.arraycopy(password, 0, buff_tmp, globalSalt.length, password.length);
		md_sha1.update(buff_tmp, 0, globalSalt.length + password.length);
		byte[] hp = md_sha1.digest();
		// CHP = SHA1(HP||ES)
		System.arraycopy(hp, 0, buff_tmp, 0, hp.length);
		System.arraycopy(entrySalt, 0, buff_tmp, hp.length, entrySalt.length);
		md_sha1.update(buff_tmp, 0, hp.length + entrySalt.length);
		byte[] chp = md_sha1.digest();	
		// k1 = CHMAC(PES||ES)
		SecretKeySpec signingKey = new SecretKeySpec(chp, HMAC_SHA1_ALGORITHM);
		mac.init(signingKey);
		byte[] k1 = mac.doFinal(pes_es);	
		// tk = CHMAC(PES)
		byte[] tk = mac.doFinal(pes);
		// k2 = CHMAC(tk||ES)
		System.arraycopy(tk, 0, buff_tmp, 0, tk.length);
		System.arraycopy(entrySalt, 0, buff_tmp, tk.length, entrySalt.length);
		mac.update(buff_tmp, 0, tk.length + entrySalt.length);
		byte[] k2 = mac.doFinal();		
		// k = k1||k2
		int klen = k1.length + k2.length;
		System.arraycopy(k1, 0, buff_tmp, 0, k1.length);
		System.arraycopy(k2, 0, buff_tmp, k1.length, k2.length);
		// That class only gets the first 24 bytes, so we don't need to care about the buff_tmp length
		DESedeKeySpec keySpec = new DESedeKeySpec(buff_tmp);
		SecretKey key = des_secKeyFactory.generateSecret(keySpec);
		byte[] desIV = Arrays.copyOfRange(buff_tmp, klen - 8, klen);
		IvParameterSpec iv = new IvParameterSpec(desIV);
		des_cipher.init(Cipher.DECRYPT_MODE, key, iv);
		try {
			return des_cipher.doFinal(cryptText);
		} catch (BadPaddingException e) {
			return null;
		}
	}	
	


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
