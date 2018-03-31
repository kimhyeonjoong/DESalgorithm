package gmail.hotjoong;

import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.DESKeySpec;
import javax.crypto.spec.DESedeKeySpec;

//java SE 9에서는 import에 문제가 있었음.
import sun.misc.BASE64Encoder;

public class DESalgorithm {

    public static void main(String[] args) throws Exception {
    		
    		//평문 메시지
        String plainText = "이것은 평문입니당.";

        String enen = encrypt(plainText);
        String dede = decrypt(enen);

        System.out.println("\n키 값: " + key());
        System.out.println("\n평문: " + plainText);
        System.out.println("\n암호화된 값: " + enen);
        System.out.println("\n복호화된 값(평문): " + dede);
    }
    
    /**
     * 키 값
     * 키 값을 바로 반환하여 키 값의 변조를 막을 수 있어 보안에 좋아 보인다.
     * @return
     */
    public static String key()
    {
        return "1234567890123456";
        //TripleDES일 경우
        //return "123456789012345678901234"; 
    }
    
    /**
     * 키 값 검사하여 DES or TripleDES 
     * 24바이트인 경우 TripleDES 아니면 DES
     * @return
     * @throws Exception
     */
    public static Key getKey() throws Exception {
        return (key().length() == 24) ? getKey2(key()) : getKey1(key());
    }

    /**
     * 지정된 비밀키를 가지고 오는 메서드 (DES)
     * require Key Size : 16 bytes
     * 
     * 키 스케쥴 과정이다.
     *
     * @return Key 비밀키 클래스
     * @exception Exception
     */
    public static Key getKey1(String keyValue) throws Exception {
    		//String형의 키를 DES 클래스로 형변환. DES키는 56비트키를 사용한다.
    		//아래 코드는 key의 최초의 8 바이트를 DES 열쇠의 키 데이터로서 사용해 DESKeySpec 객체를 생성한다.
        DESKeySpec desKeySpec = new DESKeySpec(keyValue.getBytes());
        //SecretKeyFactory는 대칭키 암호에서 사용된다.
        //DES 알고리즘의 비밀키를 SecretKeyFactory 객체 리턴한다.
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DES");
        //위에서 반환된 비밀키로부터 SecretKey 객체를 생성하고 Key 객체에 담는다.
        Key key = keyFactory.generateSecret(desKeySpec);
        return key;
    }
    
    /**
     * 지정된 비밀키를 가지고 오는 메서드 (TripleDES)
     * require Key Size : 24 bytes
     * @return
     * @throws Exception
     */
    public static Key getKey2(String keyValue) throws Exception {
        DESedeKeySpec desKeySpec = new DESedeKeySpec(keyValue.getBytes());
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DESede");
        Key key = keyFactory.generateSecret(desKeySpec);
        return key;
    }

    /**
     * 문자열 대칭 암호화
     *
     * @param ID
     *            비밀키 암호화를 희망하는 문자열
     * @return String 암호화된 ID
     * @exception Exception
     */
    public static String encrypt(String ID) throws Exception {
        if (ID == null || ID.length() == 0)
            return "";
        //DES or TripleDES를 키의 길이로 판별한다.
        String instance = (key().length() == 24) ? "DESede/ECB/PKCS5Padding" : "DES/ECB/PKCS5Padding";
        
        javax.crypto.Cipher cipher = javax.crypto.Cipher.getInstance(instance);
        //cipher객체의 암호화 모드를 정하는 메소드인듯 하다.
        cipher.init(javax.crypto.Cipher.ENCRYPT_MODE, getKey());
        String amalgam = ID;

        //첫번째 암호화 키
        byte[] inputBytes1 = amalgam.getBytes("UTF8");
        //doFinal - 평문을 암호화 하는 메서드인듯하다.
        //직접 짜보는 것을 목표로 해야겠다.
        byte[] outputBytes1 = cipher.doFinal(inputBytes1);
        sun.misc.BASE64Encoder encoder = new sun.misc.BASE64Encoder();
        //Base64 인코딩 체계를 사용하여 지정된 바이트 배열의 모든 바이트를 새로 할당 된 바이트 배열을 반환하여 String형에 담는다.
        String outputStr1 = encoder.encode(outputBytes1);
        return outputStr1;
    }

    /**
     * 문자열 대칭 복호화
     *
     * @param codedID
     *            비밀키 복호화를 희망하는 문자열
     * @return String 복호화된 ID
     * @exception Exception
     */
    
    public static String decrypt(String codedID) throws Exception {
        if (codedID == null || codedID.length() == 0)
            return "";
        
        String instance = (key().length() == 24) ? "DESede/ECB/PKCS5Padding" : "DES/ECB/PKCS5Padding";
        javax.crypto.Cipher cipher = javax.crypto.Cipher.getInstance(instance);
        cipher.init(javax.crypto.Cipher.DECRYPT_MODE, getKey());
        sun.misc.BASE64Decoder decoder = new sun.misc.BASE64Decoder();

        byte[] inputBytes1 = decoder.decodeBuffer(codedID);
        byte[] outputBytes2 = cipher.doFinal(inputBytes1);

        String strResult = new String(outputBytes2, "UTF8");
        return strResult;
    }

}

