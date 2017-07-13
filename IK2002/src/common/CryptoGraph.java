
package common;

import java.io.UnsupportedEncodingException;
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 *
 * @author M&M
 */
public class CryptoGraph {
    
    public static byte[] prf_n(int numberOfBits, byte[] keyOrRandomNo, String speceficText, byte[] sequence) {

            ByteBuffer Buffer = ByteBuffer.allocate(numberOfBits / 8);

            Key secretKey = new SecretKeySpec(keyOrRandomNo, "HmacSHA1");
            Mac msgAuthenticationCode = null;
        try {
            msgAuthenticationCode = Mac.getInstance("HmacSHA1");
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(CryptoGraph.class.getName()).log(Level.SEVERE, null, ex);
        }
        try {
            msgAuthenticationCode.init(secretKey);
        } catch (InvalidKeyException ex) {
            Logger.getLogger(CryptoGraph.class.getName()).log(Level.SEVERE, null, ex);
        }

            ByteBuffer buffer = null;
        try {
            buffer = ByteBuffer.allocate(speceficText.getBytes("UTF8").length + 1 + sequence.length + 1);
            buffer.put(speceficText.getBytes("UTF8"));
        } catch (UnsupportedEncodingException ex) {
            Logger.getLogger(CryptoGraph.class.getName()).log(Level.SEVERE, null, ex);
        }
            
            buffer.put((byte) 0x00);
            buffer.put(sequence);
            byte B = 0;
            while (B * 160 < numberOfBits) {
                buffer.put(buffer.capacity() - 1, B++);
                byte[] macResult = msgAuthenticationCode.doFinal(buffer.array());
                Buffer.put(macResult, 0, (Buffer.remaining() > 20) ? 20 : Buffer.remaining());
            }

            return Buffer.array();
    }

    public static byte[] generateMIC(byte[] k, byte[] msg) {

            Key secretKey = new SecretKeySpec(k, "HmacMD5");
            Mac msgAuthenticationCode = null;
        try {
            msgAuthenticationCode = Mac.getInstance("HmacMD5");
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(CryptoGraph.class.getName()).log(Level.SEVERE, null, ex);
        }
        try {
            msgAuthenticationCode.init(secretKey);
        } catch (InvalidKeyException ex) {
            Logger.getLogger(CryptoGraph.class.getName()).log(Level.SEVERE, null, ex);
        }
            byte[] macResult = msgAuthenticationCode.doFinal(msg);
            
            return macResult;
    }
    
        public static byte[] NonceByteSequence(byte[] mac) {
        ByteBuffer buffer = ByteBuffer.allocate(14);
        buffer.put(mac);
        buffer.putLong(System.currentTimeMillis());

        return buffer.array();
    }

    public static byte[] PTKBytesSequence(byte[] authenticatorMac, byte[] supplicantMac, byte[] authenticatorNonce, byte[] supplicantNonce) {
        ByteBuffer buffer = ByteBuffer.allocate(76);

            buffer.put(authenticatorMac);
            buffer.put(supplicantMac);

            buffer.put(authenticatorNonce);
            buffer.put(supplicantNonce);

        return buffer.array();
    }


}

