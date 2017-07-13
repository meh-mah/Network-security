
package server;

import common.CryptoGraph;
import common.EapolMsg;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.Random;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 *
 * @author M&M
 */
class ClientThread extends Thread {
    private Socket clientSocket;
    private byte[] authenticatorMac, supplicantMac;
    private byte[] pairwiseMasterKey;
    private byte[] authenticatorNonce, supplicantNonce;
    private byte[] pairwaisTransientKey;

    public ClientThread(Socket supplicantSocket, byte[] authenticatorMac, byte[] supplicantMac, byte[] pmk) {
        this.clientSocket = supplicantSocket;
        this.authenticatorMac = authenticatorMac;
        this.supplicantMac = supplicantMac;
        this.pairwiseMasterKey = pmk;
    }

    @Override
    public void run() {
        try {
           
            InputStream inStream = clientSocket.getInputStream();
            OutputStream outStream = clientSocket.getOutputStream();
            
            byte[] clientMIC, serverMIC;
            
            //calculating a random reply Counter
            Random random = new Random(System.currentTimeMillis());
            long Counter = random.nextLong();
            
           //make authenticator's Nonce
            long ran=random.nextLong();
            ByteBuffer kBuffer = ByteBuffer.allocate(8).putLong(ran);
            authenticatorNonce = CryptoGraph.prf_n(256, kBuffer.array(), "Init Counter", CryptoGraph.NonceByteSequence(authenticatorMac));
            
            System.out.println("four-way exchange using EAPOL-Key messages.");

            //Message (A): Authenticator to Supplicant
            EapolMsg msgA = new EapolMsg();
            msgA.setDescriptor((byte) 254);

           /**
            * Key Information
            * Request, Error: 0
            * Secure: 0
            * MIC: 0
            * Ack: 1
            * Install: 0
            * Index: 0
            * Key type: Pairwise
            * key Descriptor type number: 1
            */
            
            msgA.getKeyInfo().set(4, false); 
            msgA.getKeyInfo().set(5, false); 
            msgA.getKeyInfo().set(6, false); 
            msgA.getKeyInfo().set(7, false); 
            msgA.getKeyInfo().set(8, true); 
            msgA.getKeyInfo().set(9, false); 
            msgA.getKeyInfo().set(10, false); 
            msgA.getKeyInfo().set(11, false); 
            msgA.getKeyInfo().set(12, true); 
            msgA.getKeyInfo().set(13, false); 
            msgA.getKeyInfo().set(14, false); 
            msgA.getKeyInfo().set(15, true); 
            
            msgA.setLength(64);          
            msgA.setCounter(Counter);
            msgA.setNonce(authenticatorNonce);

            outStream.write(EapolMsg.eapolMsgToByteArray(msgA));
            System.out.println("Message A: ANonce sent to supplicant");

            //Message (B): Supplicant to Authenticator 
            byte[] BArrayMsgB = new byte[95];
            inStream.read(BArrayMsgB);
            EapolMsg msgB = EapolMsg.ByteArrayToEapolMsg(BArrayMsgB);
            System.out.println("message B recieved ftom supplicant");

            if (msgB.getCounter() != Counter) {
                System.out.println("ERROR: suspect to attack!\nconnection closed!");
                clientSocket.close();
                return;
            }

            supplicantNonce = msgB.getNonce();
            System.out.println("\tSupplicant's Nonce is : " + supplicantNonce.toString());

            //pairwais transient key 
            byte[]x=CryptoGraph.PTKBytesSequence(authenticatorMac, supplicantMac, authenticatorNonce, supplicantNonce);
            pairwaisTransientKey = CryptoGraph.prf_n(512, pairwiseMasterKey, "Pairwaise key expansion", x);

            clientMIC = msgB.getMIC();
            byte [] key=Arrays.copyOfRange(pairwaisTransientKey, 48, 64);
            byte[] message=Arrays.copyOfRange(EapolMsg.eapolMsgToByteArray(msgB), 0, 77);
            serverMIC = CryptoGraph.generateMIC(key, message);
            if (!Arrays.equals(serverMIC, clientMIC)) {
                System.out.println("ERROR: wrong MIC! suspect to attack! connection closed!");
                clientSocket.close();
                return;
            }
            System.out.println("\tsupplicant's MIC accepted: "+clientMIC.toString());

            //Message (C): Authenticator  to Supplicant
            EapolMsg msgC = new EapolMsg();
            
            msgC.setDescriptor((byte) 254);
            
            /**
             * Key Information:
             * Request, Error: 0
             * Secure: 0
             * MIC: 1
             * Ack: 1
             * Install: 0
             * Index: 0
             * Key type: Pairwise
             * Descriptor type: 1
             */
            
            msgC.getKeyInfo().set(4, false);
            msgC.getKeyInfo().set(5, false);
            msgC.getKeyInfo().set(6, false);
            msgC.getKeyInfo().set(7, true);
            msgC.getKeyInfo().set(8, true);
            msgC.getKeyInfo().set(9, false);
            msgC.getKeyInfo().set(10, false);
            msgC.getKeyInfo().set(11, false);
            msgC.getKeyInfo().set(12, true);
            msgC.getKeyInfo().set(13, false);
            msgC.getKeyInfo().set(14, false);
            msgC.getKeyInfo().set(15, true);
            
            msgC.setLength(64);
            msgC.setCounter(++Counter);
            msgC.setNonce(authenticatorNonce);
            msgC.setReceiveSeqCounter(0L);

            byte[] keyC=Arrays.copyOfRange(pairwaisTransientKey, 48, 64);
            byte[] messageC=Arrays.copyOfRange(EapolMsg.eapolMsgToByteArray(msgC), 0, 77);
            serverMIC = CryptoGraph.generateMIC(keyC, messageC);
            msgC.setMIC(serverMIC);
            msgC.setDataLength(0);
            
            outStream.write(EapolMsg.eapolMsgToByteArray(msgC));
            System.out.println("Message C: RSC and MIC sent to supplicant");

            //Message (D): Supplicant to Authenticator
            byte[] BArrayMsgD = new byte[95];
            inStream.read(BArrayMsgD);
            EapolMsg msgD = EapolMsg.ByteArrayToEapolMsg(BArrayMsgD);
            System.out.println("Message D recieved");

            if (msgD.getCounter() != Counter) {
                System.out.println("ERROR: suspect to attack!\nconnection closed!");
                clientSocket.close();
                return;
            }

            clientMIC = msgD.getMIC();
            byte[] keyD= Arrays.copyOfRange(pairwaisTransientKey, 48, 64);
            byte[] messageD= Arrays.copyOfRange(EapolMsg.eapolMsgToByteArray(msgD), 0, 77);
            serverMIC = CryptoGraph.generateMIC(keyD,messageD);
            if (!Arrays.equals(serverMIC, clientMIC)) {
                System.out.println("ERROR: wrong MIC! suspect to attack! connection closed!");
                clientSocket.close();
                return;
            }
            
            System.out.println("\tsupplicant's MIC accepted: "+clientMIC.toString());

            //PTK is ready to install
            System.out.println("done! keys are about to be installed");
            ByteBuffer buffer = ByteBuffer.wrap(pairwaisTransientKey);
            byte [] temp=new byte[16];
            buffer.get(temp);
            System.out.println("Data Encryption key (128 bits): " + temp.toString());
            byte [] temp1=new byte[16];
            buffer.get(temp1);
            System.out.println("Data Integrity key (128 bits): " + temp1.toString());
            byte [] temp2=new byte[16];
            buffer.get(temp2);
            System.out.println("EAPOL-Key Encryption key (128 bits): " + temp2.toString());
            byte [] temp3=new byte[16];
            buffer.get(temp3);
            System.out.println("EAPOL-Key Integrity key (128 bits): " + temp3.toString());
        } catch (IOException | ArrayIndexOutOfBoundsException ex) {
        } finally {
            try {
                clientSocket.close();
            } catch (IOException ex) {
                Logger.getLogger(ClientThread.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
    }
}
