
package server;

import java.io.IOException;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.UnknownHostException;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 *
 * @author M&M
 */
public class Authenticator {

    private static final String PMK = "IK2002";

    public static void main(String[] args) throws Exception {
        try {
            int port = 8080;

            System.out.println("waiting for client to connect.......");

            ServerSocket socket = null;
            InetAddress a = null;
            try {
                a= InetAddress.getByName("192.168.1.64");
            } catch (UnknownHostException ex) {
                Logger.getLogger(Authenticator.class.getName()).log(Level.SEVERE, null, ex);
            }

                socket = new ServerSocket(port, 5,a);
                while (true) {
                    Socket clientSocket = null;
                try {
                    clientSocket = socket.accept();
                } catch (IOException ex) {
                    Logger.getLogger(Authenticator.class.getName()).log(Level.SEVERE, null, ex);
                }
                    InetAddress ip=clientSocket.getInetAddress();
                    System.out.println("supplicant connected:: IP "+ip );
                    
                    //get authenticator's MAC address
                    InetAddress localAdd=clientSocket.getLocalAddress();
                    byte [] authenticatorMac= NetworkInterface.getByInetAddress(localAdd).getHardwareAddress();
                    if (authenticatorMac.length != 6) {
                        throw new Exception();
                    }
                    
                    //get supplicant's MAC address
                    InetAddress clientAdd=clientSocket.getInetAddress();
                    byte [] supplicantMac= NetworkInterface.getByInetAddress(clientAdd).getHardwareAddress();
                    if (supplicantMac.length != 6) {
                        throw new Exception();
                    }
                    
                    byte[] pmk =PMK.getBytes();

                    (new ClientThread(clientSocket, authenticatorMac, supplicantMac, pmk)).start();
                }
        } catch (IOException ex) {
            Logger.getLogger(Authenticator.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
}
