package test;

import java.io.IOException;
import java.math.BigInteger;   
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;   
import java.security.PublicKey;
import java.security.interfaces.RSAKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPrivateKeySpec;   
import java.security.spec.RSAPublicKeySpec;   
  
import javax.crypto.Cipher;   
  

  
  
/**   
 * @author cnchenhl   
 * Jul 8, 2011  
 */   
public class RSAMain {   
  
    private static String module = "94451776965497541750794740330619485226211211596416591512943660525607642933936858624272744324869823381046442673286565984127370198826426486274337026564822232302196702260723199394631857022407754462721391765858625309536285624807396693028681616974992683884396160528661079579474389008354226163571032039425293039173";   
    private static String exponentString = "65537";   
    private static String delement = "93039403170142435613562660047359539004661751179179179674094082618240880798421682136917703821972644277434353108310738059986124447649993357560040517935597106690580334521802057468201274030956267649326179432272234384137595343198163547427607099866012137337020271723941534689499914328149703000301215211631756899453";   
    private static String encryptString = "74C15C66DE952AB7B9B5E581940BD9B3CFA5409759E589F510EC0DC9611641BF138586A531DC9D699F67B963805EB5E126F0BE8B677754E03F2184BFA30F94B8390BA6F43D701F9601AE193D736D8EA949EA0F7DE934095ECF0795E06A2BF5A9BC937BEB5042C3A91A9996ECE8440C021170087F12CEB11F71BF23F5FB243CAA";   
    /**   
     * @param args   
     * @throws NoSuchAlgorithmException 
     * @throws IOException 
     */   
    public static void main(String[] args) throws NoSuchAlgorithmException, IOException {   
    	RSAKey[] rsakey = getKeys();
		RSAPublicKey s1 = (RSAPublicKey)rsakey[0];
		RSAPrivateKey s2 = (RSAPrivateKey)rsakey[1];
		BigInteger b = s1.getModulus();
		BigInteger b2=s1.getPublicExponent();
		
		String p1 = b.toString();
		String ss=parseByte2HexStr(removeMSZero(b.toByteArray()));
		String ss2=parseByte2HexStr((b2.toByteArray()));
		System.out.println(ss +"  _  "+ss2);
		
		String p2 = b2.toString();
		String p3 = s2.getModulus().toString();
		String p4 = s2.getPrivateExponent().toString();	
		
		System.out.println("p1:"+ p1);
		System.out.println("p2:"+ p2);
		System.out.println("p3:"+ p3);
		System.out.println("p4:"+ p4);
		
		
        byte[] en = encrypt(module,exponentString,"YUIUI55");   
        String s=parseByte2HexStr(en);
        System.out.println(s);   
       
        byte[] str=parseHexStr2Byte(encryptString);
        System.out.println(new String(Dencrypt(module,delement,str)));   
    }   
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
    public static byte[] encrypt(String modBytes ,  String expBytes,String exponentString) {   
        try {   
           
            BigInteger modulus = new BigInteger( modBytes);   
            BigInteger exponent = new BigInteger(expBytes);   
  
            RSAPublicKeySpec rsaPubKey = new RSAPublicKeySpec(modulus, exponent);   
            KeyFactory fact = KeyFactory.getInstance("RSA");   
            PublicKey pubKey = fact.generatePublic(rsaPubKey);   
  
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");   
            cipher.init(Cipher.ENCRYPT_MODE, pubKey);   
  
            byte[] cipherData = cipher.doFinal(exponentString.getBytes());   
            return cipherData;   
        } catch (Exception e) {   
            e.printStackTrace();   
        }   
        return null;   
  
    }   
  
    public static byte[] Dencrypt(String modBytes ,  String expBytes,byte[] encrypted) {   
        try {              
            BigInteger modules = new BigInteger(modBytes);   
            BigInteger exponent = new BigInteger(expBytes);   
  
            KeyFactory factory = KeyFactory.getInstance("RSA");   
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");   
  
            RSAPrivateKeySpec privSpec = new RSAPrivateKeySpec(modules, exponent);   
            PrivateKey privKey = factory.generatePrivate(privSpec);   
            cipher.init(Cipher.DECRYPT_MODE, privKey);   
            byte[] decrypted = cipher.doFinal(encrypted);   
            return decrypted;   
        } catch (Exception e) {   
            e.printStackTrace();   
        }   
        return null;   
    }   
    /**
     * 将二进制转换成16进制
     * @param buf
     * @return
     */
    public static String parseByte2HexStr(byte buf[]) {
        StringBuffer sb = new StringBuffer();
        for (int i = 0; i < buf.length; i++) {
            String hex = Integer.toHexString(buf[i] & 0xFF);
            if (hex.length() == 1) {
                hex = '0' + hex;
            }
            sb.append(hex.toUpperCase());
        }
        return sb.toString();
    }
 
    /**
     * 将16进制转换为二进制
     * @param hexStr
     * @return
     */
    public static byte[] parseHexStr2Byte(String hexStr) {
        if (hexStr.length() < 1)
            return null; 
        byte[] result = new byte[hexStr.length() / 2];
        for (int i = 0; i < hexStr.length() / 2; i++) {
            int high = Integer.parseInt(hexStr.substring(i * 2, i * 2 + 1), 16);
            int low = Integer.parseInt(hexStr.substring(i * 2 + 1, i * 2 + 2),
                    16);
            result[i] = (byte) (high * 16 + low);
        }
        return result;
    }
}  