
package common;

import java.nio.ByteBuffer;
import java.util.Arrays;
import sun.security.util.BitArray;

/**
 *
 * @author M&M
 */
public class EapolMsg {

    private byte descriptor; 
    private BitArray keyInfo;
    private int Length;
    private long counter;
    private byte[] Nonce;
    private byte[] Iv;
    private long ReceiveSeqCounter;
    private long Identifier;
    private byte[] MIC;
    private int dataLength;
    private byte[] data;

    public EapolMsg() {
        keyInfo = new BitArray(16);
        Nonce = new byte[32];
        Iv = new byte[16];
        MIC = new byte[16];
        data = new byte[0];
    }

    public static byte[] eapolMsgToByteArray(EapolMsg msg) {
        ByteBuffer buffer = ByteBuffer.allocate(95 + msg.dataLength);
        
        buffer.put(msg.descriptor);
        buffer.put(msg.keyInfo.toByteArray());

        ByteBuffer buf = ByteBuffer.allocate(4);
        buffer.put(buf.putInt(msg.Length).array(), 2, 2);

        buffer.putLong(msg.counter);

        buffer.put(msg.Nonce, 0, 32);

        buffer.put(msg.Iv, 0, 16);

        buffer.putLong(msg.ReceiveSeqCounter);

        buffer.putLong(msg.Identifier);

        buffer.put(msg.MIC, 0, 16);

        buf.clear();
        buffer.put(buf.putInt(msg.dataLength).array(), 2, 2);

        buffer.put(msg.data, 0, msg.dataLength);

        return buffer.array();
    }

    public static EapolMsg ByteArrayToEapolMsg(byte[] B) {
        ByteBuffer buffer = ByteBuffer.wrap(B);
        ByteBuffer buff;
        byte[] byt;
        EapolMsg msg = new EapolMsg();

        msg.descriptor = buffer.get();
        
        byt = new byte[2];
        buffer.get(byt);
        BitArray bitA=new BitArray(16, byt);
        msg.keyInfo=bitA;

        byt = new byte[4];
        buffer.get(byt, 2, 2);
        buff = ByteBuffer.wrap(byt);
        msg.Length = buff.getInt();

        msg.counter = buffer.getLong();
        
        buffer.get(msg.Nonce);

        buffer.get(msg.Iv);

        msg.ReceiveSeqCounter = buffer.getLong();

        msg.Identifier = buffer.getLong();

        buffer.get(msg.MIC);

        byt = new byte[4];
        buffer.get(byt, 2, 2);
        buff = ByteBuffer.wrap(byt);
        msg.dataLength = buff.getInt();

        int l=msg.dataLength;
        msg.data = new byte[l];
        buffer.get(msg.data, 0, l);

        return msg;
    }

    @Override
    public boolean equals(Object o) {
        final EapolMsg otherMsg = (EapolMsg) o;
        if (o == null || 
                getClass() != o.getClass() || 
                this.descriptor != otherMsg.descriptor || 
                (this.keyInfo != otherMsg.keyInfo && (this.keyInfo == null || !this.keyInfo.equals(otherMsg.keyInfo)))||
                this.Length != otherMsg.Length ||
                this.counter != otherMsg.counter ||
                !Arrays.equals(this.Nonce, otherMsg.Nonce)||
                !Arrays.equals(this.Iv, otherMsg.Iv)||
                this.ReceiveSeqCounter != otherMsg.ReceiveSeqCounter ||
                this.Identifier != otherMsg.Identifier ||
                !Arrays.equals(this.MIC, otherMsg.MIC) ||
                this.dataLength != otherMsg.dataLength ||
                !Arrays.equals(this.data, otherMsg.data)) {
            
            return false;
        }
        return true;
    }

    @Override
    public int hashCode() {
        int hash = 63;
        hash = 213 * hash + this.descriptor;
        hash = 213 * hash + (this.keyInfo != null ? this.keyInfo.hashCode() : 0);
        hash = 213 * hash + this.Length;
        hash = 213 * hash + (int) (this.counter ^ (this.counter >>> 32));
        hash = 213 * hash + Arrays.hashCode(this.Nonce);
        hash = 213 * hash + Arrays.hashCode(this.Iv);
        hash = 213 * hash + (int) (this.ReceiveSeqCounter ^ (this.ReceiveSeqCounter >>> 32));
        hash = 213 * hash + (int) (this.Identifier ^ (this.Identifier >>> 32));
        hash = 213 * hash + Arrays.hashCode(this.MIC);
        hash = 213 * hash + this.dataLength;
        hash = 213 * hash + Arrays.hashCode(this.data);
        return hash;
    }

    public byte getDescriptor() {
        return descriptor;
    }

    public byte[] getIv() {
        return Iv;
    }

    public byte[] getData() {
        return data;
    }

    public int getDataLength() {
        return dataLength;
    }

    public long getIdentifier() {
        return Identifier;
    }

    public BitArray getKeyInfo() {
        return keyInfo;
    }

    public int getKeyLength() {
        return Length;
    }

    public byte[] getMIC() {
        return MIC;
    }

    public byte[] getNonce() {
        return Nonce;
    }

    public long getReceiveSeqCounter() {
        return ReceiveSeqCounter;
    }

    public long getCounter() {
        return counter;
    }

    public void setDescriptor(byte desType) {
        this.descriptor = desType;
    }


    public void setDataLength(int Length) {
        this.dataLength = Length;
    }

    public void setKeyIdentifier(long keyIdentifier) {
        this.Identifier = keyIdentifier;
    }

    public void setLength(int length) {
        this.Length = length;
    }

    public void setMIC(byte[] MIC) {
        this.MIC = MIC;
    }

    public void setNonce(byte[] nonce) {
        this.Nonce = nonce;
    }

    public void setReceiveSeqCounter(long ReceiveSeqCounter) {
        this.ReceiveSeqCounter = ReceiveSeqCounter;
    }

    public void setCounter(long counter) {
        this.counter = counter;
    }

}

