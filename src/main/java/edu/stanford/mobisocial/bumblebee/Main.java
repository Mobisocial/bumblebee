package edu.stanford.mobisocial.bumblebee;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.PublicKey;
import java.security.PrivateKey;
import java.io.IOException;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.DataInputStream;
import java.io.FileInputStream;
import java.io.File;
import java.util.*;
import java.security.KeyFactory;
import java.security.spec.X509EncodedKeySpec;
import edu.stanford.mobisocial.bumblebee.util.*;


public class Main {

	public static PrivateKey loadPrivateKey(String filename) {
		try {
			File f = new File(filename);
			FileInputStream fis = new FileInputStream(f);
			DataInputStream dis = new DataInputStream(fis);
			byte[] keyBytes = new byte[(int) f.length()];
			dis.readFully(keyBytes);
			dis.close();

			PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
			KeyFactory kf = KeyFactory.getInstance("RSA");

			return kf.generatePrivate(spec);
		} catch (Exception e) {
			e.printStackTrace(System.err);
			System.exit(0);

			return null;
		}
	}

    public static String makePersonIdForPublicKey(PublicKey key){
		String me = null;
		try {
			me = Util.SHA1(key.getEncoded());
		} catch (Exception e) {
			throw new IllegalArgumentException(
                "Could not compute SHA1 of public key.");
		}
		return me.substring(0, 10);
    }

	public static PublicKey loadPublicKey(String filename) {
		try {
			File f = new File(filename);
			FileInputStream fis = new FileInputStream(f);
			DataInputStream dis = new DataInputStream(fis);
			byte[] keyBytes = new byte[(int) f.length()];
			dis.readFully(keyBytes);
			dis.close();

			X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
			KeyFactory kf = KeyFactory.getInstance("RSA");

			return kf.generatePublic(spec);
		} catch (Exception e) {
			e.printStackTrace(System.err);
			System.exit(0);

			return null;
		}
	}

	public static void main(String[] args) {
		final String myKeyPrefix = args[0];
		final String otherKeyPrefix = args[1];
		final PublicKey myPubKey = loadPublicKey("etc/" + myKeyPrefix
                                                 + "_public_key.der");
		final PrivateKey myPrivKey = loadPrivateKey("etc/" + myKeyPrefix
                                                    + "_private_key.der");
		final PublicKey otherPubKey = loadPublicKey("etc/" + otherKeyPrefix
                                                    + "_public_key.der");

        System.out.println(Base64.encodeToString(myPubKey.getEncoded(), false));

        TransportIdentityProvider ident = new TransportIdentityProvider(){
                public PublicKey userPublicKey() { return myPubKey; }
                public PrivateKey userPrivateKey(){ return myPrivKey; }
                public String userPersonId(){ return personIdForPublicKey(userPublicKey()); }
                public PublicKey publicKeyForPersonId(String id){
                    if(id.equals(personIdForPublicKey(myPubKey))){
                        return myPubKey;
                    }
                    else if(id.equals(personIdForPublicKey(otherPubKey))) {
                        return otherPubKey;
                    }
                    return null;
                }
                public String personIdForPublicKey(PublicKey key){
                    return makePersonIdForPublicKey(key);
                }
            };
        ConnectionStatus status = new ConnectionStatus(){
                public boolean isConnected(){ return true; }
            };
        MessengerService m = new XMPPMessengerService(ident, status);
		m.addStateListener(new StateListener() {
                public void onReady() {
                    System.out.println("READY!");
                }

                public void onNotReady() {
                }
            });
		m.addMessageListener(new MessageListener() {
                public void onMessage(IncomingMessage m) {
                    System.out.println("Got message! " + m.toString());
                }
            });

		m.init();

		try {
			String curLine = ""; // Line read from standard in
			InputStreamReader converter = new InputStreamReader(System.in);
			BufferedReader in = new BufferedReader(converter);

			while (!(curLine.equals("q"))) {
				curLine = in.readLine();

				final String line = curLine;

				if (!(curLine.equals("q"))) {
					m.sendMessage(new OutgoingMessage() {
                            public List<PublicKey> toPublicKeys() {
                                return Collections.singletonList(otherPubKey);
                            }
                            public String contents() {
                                return line;
                            }
                        });
					System.out.println("You typed: " + curLine);
				}
			}
		} catch (IOException e) {
			e.printStackTrace(System.err);
		}
	}
}
