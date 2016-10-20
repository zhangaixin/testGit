package test;



import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;

import javax.crypto.Cipher;

public class Rsa {

	/**
	 * 生成公钥和私钥
	 * @throws NoSuchAlgorithmException 
	 *
	 */
	public static RSAKey[] getKeys() throws NoSuchAlgorithmException{
		KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");
        keyPairGen.initialize(1024);
        KeyPair keyPair = keyPairGen.generateKeyPair();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
        RSAKey[] rsakey = new RSAKey[]{publicKey, privateKey};
        return rsakey;
	}
	/**
	 * 使用模和指数生成RSA公钥
	 * 注意：【此代码用了默认补位方式，为RSA/None/PKCS1Padding，不同JDK默认的补位方式可能不同，如Android默认是RSA
	 * /None/NoPadding】
	 * 
	 * @param modulus
	 *            模
	 * @param exponent
	 *            指数
	 * @return
	 */
	public static RSAPublicKey getPublicKey(String modulus, String exponent) {
		try {
			BigInteger b1 = new BigInteger(modulus);
			BigInteger b2 = new BigInteger(exponent);
			//byte[] by = removeMSZero(b1.toByteArray());
			//String a1 = new BASE64Encoder().encode(by);
			//String a2 = new BASE64Encoder().encode(removeMSZero(b2.toByteArray()));
            //System.out.print(a1);
            //System.out.print(a2);
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			RSAPublicKeySpec keySpec = new RSAPublicKeySpec(b1, b2);
			return (RSAPublicKey) keyFactory.generatePublic(keySpec);
		} catch (Exception e) {
			e.printStackTrace();
			return null;
		}
	}
	/** 
     * @param data 
     * @return 
     */  
    private static byte[] removeMSZero(byte[] data) {  
        byte[] data1;  
        int len = data.length;  
        if (data[0] == 0) {  
            data1 = new byte[data.length - 1];  
            System.arraycopy(data, 1, data1, 0, len - 1);  
        } else  
            data1 = data;  
  
        return data1;  
    }      

	/**
	 * 使用模和指数生成RSA私钥
	 * 注意：【此代码用了默认补位方式，为RSA/None/PKCS1Padding，不同JDK默认的补位方式可能不同，如Android默认是RSA
	 * /None/NoPadding】
	 * 
	 * @param modulus
	 *            模
	 * @param exponent
	 *            指数
	 * @return
	 */
	public static RSAPrivateKey getPrivateKey(String modulus, String exponent) {
		try {
			BigInteger b1 = new BigInteger(modulus);
			BigInteger b2 = new BigInteger(exponent);
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			RSAPrivateKeySpec keySpec = new RSAPrivateKeySpec(b1, b2);
			return (RSAPrivateKey) keyFactory.generatePrivate(keySpec);
		} catch (Exception e) {
			e.printStackTrace();
			return null;
		}
	}

	/**
	 * 公钥加密
	 * 
	 * @param data
	 * @param publicKey
	 * @return
	 * @throws Exception
	 */
	public static String encryptByPublicKey(String data, RSAPublicKey publicKey)
			throws Exception {
		Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		cipher.init(Cipher.ENCRYPT_MODE, publicKey);
		// 模长
		int key_len = publicKey.getModulus().bitLength() / 8;
		// 加密数据长度 <= 模长-11
		String[] datas = splitString(data, key_len - 11);
		String mi = "";
		//如果明文长度大于模长-11则要分组加密
		for (String s : datas) {
			mi += bcd2Str(cipher.doFinal(s.getBytes()));
		}
		return mi;
	}
	
	public static String encryptByPublicKey(String modulus, String exponent,String data)
			throws Exception {
		RSAPublicKey publicKey = getPublicKey(modulus, exponent);
		Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		cipher.init(Cipher.ENCRYPT_MODE, publicKey);
		// 模长
		int key_len = publicKey.getModulus().bitLength() / 8;
		// 加密数据长度 <= 模长-11
		String[] datas = splitString(data, key_len - 11);
		String mi = "";
		//如果明文长度大于模长-11则要分组加密
		for (String s : datas) {
			mi += bcd2Str(cipher.doFinal(s.getBytes()));
		}
		return mi;
	}

	/**
	 * 私钥解密
	 * 
	 * @param data
	 * @param privateKey
	 * @return
	 * @throws Exception
	 */
	public static String decryptByPrivateKey(String data, RSAPrivateKey privateKey)
			throws Exception {
		Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		cipher.init(Cipher.DECRYPT_MODE, privateKey);
		//模长
		int key_len = privateKey.getModulus().bitLength() / 8;
		byte[] bytes = data.getBytes();
		byte[] bcd = ASCII_To_BCD(bytes, bytes.length);
		System.err.println(bcd.length);
		//如果密文长度大于模长则要分组解密
		String ming = "";
		byte[][] arrays = splitArray(bcd, key_len);
		for(byte[] arr : arrays){
			ming += new String(cipher.doFinal(arr));
		}
		return ming;
	}
	/**
	 * ASCII码转BCD码
	 * 
	 */
	public static byte[] ASCII_To_BCD(byte[] ascii, int asc_len) {
		byte[] bcd = new byte[asc_len / 2];
		int j = 0;
		for (int i = 0; i < (asc_len + 1) / 2; i++) {
			bcd[i] = asc_to_bcd(ascii[j++]);
			bcd[i] = (byte) (((j >= asc_len) ? 0x00 : asc_to_bcd(ascii[j++])) + (bcd[i] << 4));
		}
		return bcd;
	}
	public static byte asc_to_bcd(byte asc) {
		byte bcd;

		if ((asc >= '0') && (asc <= '9'))
			bcd = (byte) (asc - '0');
		else if ((asc >= 'A') && (asc <= 'F'))
			bcd = (byte) (asc - 'A' + 10);
		else if ((asc >= 'a') && (asc <= 'f'))
			bcd = (byte) (asc - 'a' + 10);
		else
			bcd = (byte) (asc - 48);
		return bcd;
	}
	/**
	 * BCD转字符串
	 */
	public static String bcd2Str(byte[] bytes) {
		char temp[] = new char[bytes.length * 2], val;

		for (int i = 0; i < bytes.length; i++) {
			val = (char) (((bytes[i] & 0xf0) >> 4) & 0x0f);
			temp[i * 2] = (char) (val > 9 ? val + 'A' - 10 : val + '0');

			val = (char) (bytes[i] & 0x0f);
			temp[i * 2 + 1] = (char) (val > 9 ? val + 'A' - 10 : val + '0');
		}
		return new String(temp);
	}
	/**
	 * 拆分字符串
	 */
	public static String[] splitString(String string, int len) {
		int x = string.length() / len;
		int y = string.length() % len;
		int z = 0;
		if (y != 0) {
			z = 1;
		}
		String[] strings = new String[x + z];
		String str = "";
		for (int i=0; i<x+z; i++) {
			if (i==x+z-1 && y!=0) {
				str = string.substring(i*len, i*len+y);
			}else{
				str = string.substring(i*len, i*len+len);
			}
			strings[i] = str;
		}
		return strings;
	}
	/**
	 *拆分数组 
	 */
	public static byte[][] splitArray(byte[] data,int len){
		int x = data.length / len;
		int y = data.length % len;
		int z = 0;
		if(y!=0){
			z = 1;
		}
		byte[][] arrays = new byte[x+z][];
		byte[] arr;
		for(int i=0; i<x+z; i++){
			arr = new byte[len];
			if(i==x+z-1 && y!=0){
				System.arraycopy(data, i*len, arr, 0, y);
			}else{
				System.arraycopy(data, i*len, arr, 0, len);
			}
			arrays[i] = arr;
		}
		return arrays;
	}
	 
    //测试用例
    public static void test1(){
    	String str = "a123";
		try {
			String modulus="126452507187668126133704598904467409293930267627490254080462993467229264910034561280495011151329690409710639151693183438904197257827237032800228236877208463361612016072777866421723597903400725127298871906183478562279479298615412709148013501900716339308016447368649403433754276127546383619090605854382191666491";
			String exponent="65537";
			RSAPublicKey publicKey = getPublicKey(modulus, exponent);
			String desStr = encryptByPublicKey(str, publicKey);
			desStr="oL9PdBev4avT9+2pBUUSWjM1udrMU8ePGXFBprn5t1e7KzhKfzoVmukoqLfNHfp37cHdi+fPlHTTnfaCy+qA7kVVz+aPAWedYz12uHE5X3bBtq00pCKc6X2FZnbwISo3zHiGOOuDBbkIMOfxKGG5V6CalIccBow3eU6OlxInOLg=";
			System.out.println("加密后:" + desStr);
			RSAPrivateKey privateKey = getPrivateKey(modulus, "2651109218851274933361461752822653163401745391460878726620934022368631612469101228304624034086500673252398159733073440118625616556366993958641890801673625550597265413918767215723265679237990140300817865591754798995971254513039867643315730711947637898707979768392190774144703593888649904476986854308288667537");
			byte[] bytes = new BASE64Decoder().decodeBuffer(desStr);//.getBytes();
			String str2 = decryptByPrivateKey(bytes, privateKey);
			System.out.println("解密后："+ str2 );
		} catch (Exception e) {
			e.printStackTrace();
		}       
        
    }
    public static void main3(String[] args) throws Exception {
    	RSAKey[] rsakey = getKeys();
		RSAPublicKey s1 = (RSAPublicKey)rsakey[0];
		RSAPrivateKey s2 = (RSAPrivateKey)rsakey[1];
		
		String p1 = s1.getModulus().toString();
		String p2 = s1.getPublicExponent().toString();
		String p3 = s2.getModulus().toString();
		String p4 = s2.getPrivateExponent().toString();
		
		//getPrivateKey(modulus, exponent);
		
		System.out.println("p1:"+ p1);
		System.out.println("p2:"+ p2);
		System.out.println("p3:"+ p3);
		System.out.println("p4:"+ p4);
		
    	}

    public static void main(String[] args) {
        test1();
    }
}
