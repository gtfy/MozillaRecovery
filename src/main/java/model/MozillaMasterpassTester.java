package model;

import java.io.UnsupportedEncodingException;
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
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.DESedeKeySpec;
import javax.crypto.spec.IvParameterSpec;

import org.apache.log4j.Logger;

public class MozillaMasterpassTester {
	// TODO: write some test cases
	private final static Logger logger = Logger.getLogger(MozillaMasterpassTester.class);
	
	private static final String PASSWORD_CHECK_STR = "password-check";
	private static final byte[] PASSWORD_CHECK_BYTES = PASSWORD_CHECK_STR.getBytes();
	private static final String SHA1_ALGORITHM = "SHA-1";
	private static final int hmac_blocksize = 64;
	
	private final MessageDigest md_sha1;
	private final Cipher des_cipher;
	private final SecretKeyFactory des_secKeyFactory;
	// We need a lot of temporary variables and arrays
	// which we are going to reuse
	private byte[] pes_es;
	private byte[] pes;
	private final byte hp[] = new byte[20];
	private final byte chp[] = new byte[20];
	private final byte k1[] = new byte[20];
	private final byte tk[] = new byte[20];
	private final byte k2[] = new byte[20];
	private final byte o_key[] = new byte[hmac_blocksize];
	private final byte i_key[] = new byte[hmac_blocksize];
	private final byte hmac_tmp[] = new byte[hmac_blocksize];
	// We (re)use this buffer for key concatenating and such
	// TODO: 2048 should be enough, but CHECK IT !! 1!!
	// it should be max userpass + 40 ?!
	private final byte[] buff_tmp = new byte[2048];
	
	private final byte[] entrySalt;
	private final byte[] globalSalt;
	private final byte[] encPasswordCheck;

	public MozillaMasterpassTester(byte entrySalt[], byte globalSalt[], byte encPasswordCheck[]) throws NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException {
		this.entrySalt = entrySalt;
		this.globalSalt = globalSalt;
		this.encPasswordCheck = encPasswordCheck;
		
		this.pes = Arrays.copyOf(entrySalt, 20);
		this.pes_es = Arrays.copyOf(entrySalt, 40);			
		System.arraycopy(entrySalt, 0, pes_es, 20, 20);
		
		md_sha1 = MessageDigest.getInstance(SHA1_ALGORITHM);
		des_cipher = Cipher.getInstance("DESede/CBC/PKCS5Padding", "SunJCE");
		des_secKeyFactory =  SecretKeyFactory.getInstance("DESede");
		
		// pad the key arrays once, as every used key will be exact 20 bytes
		for (int i = 20; i < hmac_blocksize; i_key[i] = (byte) (0 ^ 0x36), i++);
		for (int i = 20; i < hmac_blocksize; o_key[i] = (byte) (0 ^ 0x5c), i++);
		
		logger.debug("Starting with entry salt: " + Arrays.toString(entrySalt)
				+ "\nglobal salt: " + Arrays.toString(globalSalt)
				+ "\nencrypted password check: " + Arrays.toString(encPasswordCheck)
				);
	}
	
	public boolean isMasterpass(byte password[]) throws DigestException, InvalidKeyException, InvalidKeySpecException, InvalidAlgorithmParameterException, ShortBufferException, IllegalBlockSizeException{
		int i;
		// HP = SHA1(global-salt||password)
		System.arraycopy(globalSalt, 0, buff_tmp, 0, globalSalt.length);
		System.arraycopy(password, 0, buff_tmp, globalSalt.length, password.length);
		md_sha1.update(buff_tmp, 0, globalSalt.length + password.length);
		md_sha1.digest(hp, 0, 20);
		// CHP = SHA1(HP||ES)
		System.arraycopy(hp, 0, buff_tmp, 0, 20);
		System.arraycopy(entrySalt, 0, buff_tmp, 20, 20);
		md_sha1.update(buff_tmp, 0, 40);
		md_sha1.digest(chp, 0, 20);
		// create keys for hmac (mac.init())
		for (i = 0; i < 20; i_key[i] = (byte) (chp[i] ^ 0x36), o_key[i] = (byte) (chp[i] ^ 0x5c), i++);
		// k1 = CHMAC(PES||ES)
		md_sha1.update(i_key);
		md_sha1.update(pes_es);
		md_sha1.digest(hmac_tmp, 0, 20);
		md_sha1.update(o_key, 0, hmac_blocksize);
		md_sha1.update(hmac_tmp, 0, 20);
		md_sha1.digest(k1, 0, 20);
		// tk = CHMAC(PES)
		md_sha1.update(i_key);
		md_sha1.update(pes);
		md_sha1.digest(hmac_tmp, 0, 20);
		md_sha1.update(o_key, 0, hmac_blocksize);
		md_sha1.update(hmac_tmp, 0, 20);
		md_sha1.digest(tk, 0, 20);
		// k2 = CHMAC(tk||ES)
		System.arraycopy(tk, 0, buff_tmp, 0, 20);
		System.arraycopy(entrySalt, 0, buff_tmp, 20, 20);
		md_sha1.update(i_key);
		md_sha1.update(buff_tmp, 0, 40);
		md_sha1.digest(hmac_tmp, 0, 20);
		md_sha1.update(o_key, 0, hmac_blocksize);
		md_sha1.update(hmac_tmp, 0, 20);
		md_sha1.digest(k2, 0, 20);
		// k = k1||k2
		System.arraycopy(k1, 0, buff_tmp, 0, 20);
		System.arraycopy(k2, 0, buff_tmp, 20, 20);
		// That class only gets the first 24 bytes, so we don't need to care about the buff_tmp length
		DESedeKeySpec keySpec = new DESedeKeySpec(buff_tmp);
		SecretKey key = des_secKeyFactory.generateSecret(keySpec);
		IvParameterSpec iv = new IvParameterSpec(buff_tmp, 40-8, 8);
		des_cipher.init(Cipher.DECRYPT_MODE, key, iv);
		try {
			if (des_cipher.doFinal(encPasswordCheck, 0, encPasswordCheck.length, buff_tmp) != PASSWORD_CHECK_BYTES.length){
				return false;
			}
		} catch (BadPaddingException e) {
			return false;
		}
		
		for (i = 0; i < PASSWORD_CHECK_BYTES.length && PASSWORD_CHECK_BYTES[i] == buff_tmp[i]; i++);
		return i == PASSWORD_CHECK_BYTES.length;
	}
	
	
	
	public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, InvalidKeyException, DigestException, InvalidKeySpecException, InvalidAlgorithmParameterException, ShortBufferException, IllegalBlockSizeException, UnsupportedEncodingException {
		byte[] entrySalt = new byte[]{53, -6, -120, -124, -21, 49, 69, -22, -126, -75, 53, -18, 7, -65, -70, -9, -68, 32, -75, 127};
		byte[] globalSalt = new byte[]{65, -34, 9, -104, -89, -49, 26, -86, -67, 26, 1, 54, -13, 115, 122, 7, -62, -22, 114, 45};
		byte[] encPwTest = new byte[]{47, 54, 67, -122, -38, -79, -91, -59, 41, 57, 44, -24, 27, 17, 59, 59};
		MozillaMasterpassTester pwTester = new MozillaMasterpassTester(entrySalt, globalSalt, encPwTest);
		System.out.println("Password test (correct pass): " + pwTester.isMasterpass("test12".getBytes("UTF-8")));
		
		byte wrongPass[] = "notThePassYouAreLookingFor".getBytes("UTF-8");
		int testSize = 500000;
		long sTime = -System.currentTimeMillis();
		for (int i = 0; i < testSize; i++) {
			pwTester.isMasterpass(wrongPass);
		}
		sTime += System.currentTimeMillis();
		System.out.println("Speed: " + testSize/(sTime/1000.0));
	}
}
