
package client;

import common.CryptoGraph;
import common.EapolMsg;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.Random;
import java.util.Scanner;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 *
 * @author M&M
 */
public class Supplicant {

    private Socket clientSocket;
    private byte[] authenticatorMac, supplicantMac;
    private byte[] pairwiseMasterKey;
    private byte[] authenticatorNonce, supplicantNonce;
    private byte[] pairwiseTransientKey;

    private void connect(String ip, int port) {
        try {
            clientSocket = new Socket(ip, port);
            System.out.println("Start to connect...");
            
            //get Authenticator's mac
            InetAddress add=clientSocket.getInetAddress();
            authenticatorMac =NetworkInterface.getByInetAddress(add).getHardwareAddress();
            if (authenticatorMac.length != 6) {
            throw new Exception();
        }       
            //get supplicant's mac
            InetAddress addS=clientSocket.getLocalAddress();
            supplicantMac= NetworkInterface.getByInetAddress(addS).getHardwareAddress();
            if (supplicantMac.length != 6) {
            throw new Exception();
        }
            
        } catch (Exception ex) {
            Logger.getLogger(Supplicant.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    private void exchangeMessages() {
        try {           
            InputStream inStream = clientSocket.getInputStream();
            OutputStream outStream = clientSocket.getOutputStream();
            Random random = new Random(System.currentTimeMillis());
            long Counter;
            byte[] serverMIC, clientMIC;
            System.out.println("four-way exchange using EAPOL-Key messages.");

            //make supplicant's Nonce
            long ran=random.nextLong();
            ByteBuffer kBuffer = ByteBuffer.allocate(8).putLong(ran);
            byte[] byteSequence=CryptoGraph.NonceByteSequence(supplicantMac);
            supplicantNonce = CryptoGraph.prf_n(256, kBuffer.array(), "Init Counter", byteSequence);

            //Message (A): Authenticator to Supplicant
            byte[] bArrayMsgA = new byte[95];
            inStream.read(bArrayMsgA);
            EapolMsg msgA = EapolMsg.ByteArrayToEapolMsg(bArrayMsgA);
            System.out.println("message A received ftom authenticator");

            Counter = msgA.getCounter();

            authenticatorNonce = msgA.getNonce();
            System.out.println("\tAuthenticator's Nonce = " + authenticatorNonce.toString());

            //pairwais transient key
            byte[] sequence=CryptoGraph.PTKBytesSequence(authenticatorMac, supplicantMac, authenticatorNonce, supplicantNonce);
            pairwiseTransientKey = CryptoGraph.prf_n(512, pairwiseMasterKey, "Pairwaise key expansion", sequence);

            //Message (B): Supplicant to Authenticator
            EapolMsg msgB = new EapolMsg();
            msgB.setDescriptor((byte) 254);
            /**
             * Key Information
             * Request, Error: 0
             * Secure: 0
             * MIC: 1
             * Ack: 0
             * Install: 0
             * Index: 0
             * Key type: Pairwise
             * Descriptor type: 1
             */
            msgB.getKeyInfo().set(4, false);
            msgB.getKeyInfo().set(5, false);
            msgB.getKeyInfo().set(6, false);
            msgB.getKeyInfo().set(7, true);
            msgB.getKeyInfo().set(8, false);
            msgB.getKeyInfo().set(9, false);
            msgB.getKeyInfo().set(10, false);
            msgB.getKeyInfo().set(11, false);
            msgB.getKeyInfo().set(12, true);
            msgB.getKeyInfo().set(13, false);
            msgB.getKeyInfo().set(14, false);
            msgB.getKeyInfo().set(15, true);
            
            msgB.setLength(64);
            msgB.setCounter(Counter);
            msgB.setNonce(supplicantNonce);
            msgB.setKeyIdentifier(0L);
            
            byte[] key= Arrays.copyOfRange(pairwiseTransientKey, 48, 64);
            byte[] message= Arrays.copyOfRange(EapolMsg.eapolMsgToByteArray(msgB), 0, 77);
            clientMIC = CryptoGraph.generateMIC(key, message);
            msgB.setMIC(clientMIC);
            msgB.setDataLength(0); 
      
            outStream.write(EapolMsg.eapolMsgToByteArray(msgB));
            System.out.println("Message B: Nonce and MIC sent to Authonticator");

            //Message (C): Authenticator  to Supplicant
            byte[] bArrayC = new byte[95];
            inStream.read(bArrayC);
            EapolMsg msgC = EapolMsg.ByteArrayToEapolMsg(bArrayC);
            System.out.println("message C recieved ftom authenticator");

            if (msgC.getCounter() != ++Counter) {
                System.out.println("ERROR: suspect to attack!\nconnection closed!");
                clientSocket.close();
                return;
            }

            serverMIC = msgC.getMIC();
            byte [] keyC=Arrays.copyOfRange(pairwiseTransientKey, 48, 64);
            byte [] messageC= Arrays.copyOfRange(EapolMsg.eapolMsgToByteArray(msgC), 0, 77);
            clientMIC = CryptoGraph.generateMIC(keyC, messageC);
            if (!Arrays.equals(clientMIC, serverMIC)) {
                System.out.println("ERROR: wrong MIC! suspect to attack! connection closed!");
                clientSocket.close();
                return;
            }
            System.out.println("\tAthenticator's MIC accepted: "+serverMIC.toString());
            System.out.println("\tKey Sequence Start = " + msgC.getReceiveSeqCounter());


            //Message (D): Supplicant to Authenticator
            EapolMsg msgD = new EapolMsg();
            msgD.setDescriptor((byte) 254);
            /**
             * Key Information
             * Request, Error: 0
             * Secure: 0
             * MIC: 1
             * Ack: 0
             * Install: 1
             * Index: 0
             * Key type: Pairwise
             * Descriptor type: 1
             */

            msgD.getKeyInfo().set(4, false);
            msgD.getKeyInfo().set(5, false);
            msgD.getKeyInfo().set(6, false);
            msgD.getKeyInfo().set(7, true);
            msgD.getKeyInfo().set(8, false);
            msgD.getKeyInfo().set(9, true);
            msgD.getKeyInfo().set(10, false);
            msgD.getKeyInfo().set(11, false);
            msgD.getKeyInfo().set(12, true);
            msgD.getKeyInfo().set(13, false);
            msgD.getKeyInfo().set(14, false);
            msgD.getKeyInfo().set(15, true);
            
            msgD.setLength(64);
            msgD.setCounter(Counter);
            msgD.setNonce(supplicantNonce);
            msgD.setKeyIdentifier(0L);
            
            byte[] keyD= Arrays.copyOfRange(pairwiseTransientKey, 48, 64);
            byte[] messageD= Arrays.copyOfRange(EapolMsg.eapolMsgToByteArray(msgD), 0, 77);
            clientMIC = CryptoGraph.generateMIC(keyD,messageD);
            msgD.setMIC(clientMIC);
            msgD.setDataLength(0);

            outStream.write(EapolMsg.eapolMsgToByteArray(msgD));
            System.out.println("Message D sent to authenticator");

            //PTK is ready to install
            System.out.println("done! keys are about to be installed");
            ByteBuffer buffer = ByteBuffer.wrap(pairwiseTransientKey);
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
        } catch (Exception ex) {
        } finally {
            try {
                clientSocket.close();
            } catch (IOException ex) {
                Logger.getLogger(Supplicant.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
    }


    public static void main(String[] args) {
        int port = 8080;
        String ip = "192.168.1.64";

        Scanner scanner = new Scanner (System.in);
        System.out.print("Enter PMK:\n");  
        String pmk = scanner.next(); 

        Supplicant s = new Supplicant();
        s.pairwiseMasterKey=pmk.getBytes();
        s.connect(ip, port);
        s.exchangeMessages();
    }
}
