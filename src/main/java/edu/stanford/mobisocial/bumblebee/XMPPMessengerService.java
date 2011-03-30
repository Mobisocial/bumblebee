package edu.stanford.mobisocial.bumblebee;
import org.jivesoftware.smack.filter.PacketTypeFilter;
import org.jivesoftware.smack.*;
import org.jivesoftware.smack.filter.PacketFilter;
import org.jivesoftware.smack.packet.Message;
import org.jivesoftware.smack.packet.Packet;

import java.security.PublicKey;
import java.util.*;
import java.util.concurrent.*;

public class XMPPMessengerService extends MessengerService {
	private XMPPConnection mConnection = null;
	private XMPPMessageFormat mFormat = null;
	private String mUsername = null;
	private String mPassword = null;
	private LinkedBlockingQueue<OutgoingMessage> mSendQ = 
        new LinkedBlockingQueue<OutgoingMessage>();
	public static final String XMPP_SERVER = "prpl.stanford.edu";
	private Thread sendWorker = new Thread() {
            @Override
            public void run() {
                while (true) {
                    try {
                        OutgoingMessage m = mSendQ.peek();
                        if (connectedToInternet() && (m != null) && connected()) {
                            System.out
								.println("Pulled message off sendQueue. Sending.");
                            mSendQ.poll();

                            String plain = m.contents();

                            try {
                                String cypher = mFormat.prepareOutgoingMessage(
									plain, m.toPublicKey());
                                Message msg = new Message();
                                msg.setFrom(mUsername + "@" + XMPP_SERVER);
                                msg.setBody(cypher);

                                String jid = identity().personIdForPublicKey(m.toPublicKey())
									+ "@" + XMPP_SERVER;
                                msg.setTo(jid);
                                mConnection.sendPacket(msg);
                            } catch (CryptoException e) {
                                e.printStackTrace(System.err);
                            }
                        } 
                        else {
                            if(connectedToInternet() && !connected()){
                                System.out.println("Oops! Not connected. Trying to connect....");
                                reconnect();
                            }
                            Thread.sleep(1000);
                        }
                    } catch (InterruptedException e) {
                    }
                }
            }
        };

	public XMPPMessengerService(TransportIdentityProvider ident, ConnectionStatus status) {
		super(ident, status);
		mUsername = ident.userPersonId();
		mPassword = mUsername + "pass";
		sendWorker.start();
        mFormat = new XMPPMessageFormat(ident);
	}

    synchronized private void reconnect(){
		if ((mUsername == null) || (mPassword == null)) {
			throw new IllegalArgumentException(
                "Must supply username and password.");
		}

        try{
            if(mConnection != null){
                mConnection.disconnect();
            }
        }
        catch(Exception e){
        }

		try {
			mConnection = new XMPPConnection(XMPP_SERVER);
            System.out.println("Connecting...");
			mConnection.connect();
            addHandlers(mConnection);

			AccountManager mgr = mConnection.getAccountManager();
			Map<String, String> atts = new HashMap<String, String>();
			atts.put("name", "AnonUser");
			atts.put("email", "AnonUser@" + XMPP_SERVER);
			try {
                System.out.println("Logging in with " + mUsername + " " + mPassword);
				mConnection.login(mUsername, mPassword);
				System.out.println("Logged in!");
				signalReady();
			} catch (XMPPException e) {
				try {
					System.out
                        .println("Login failed. Attempting to create account..");
					mgr.createAccount(mUsername, mPassword, atts);
					System.out.println("Account created, logging in...");
                    removeHandlers(mConnection);
                    mConnection.disconnect();

                    mConnection = new XMPPConnection(XMPP_SERVER);
                    mConnection.connect();
                    addHandlers(mConnection);
					try {
						mConnection.login(mUsername, mPassword);
						System.out.println("Logged in!");
                        signalReady();
					} catch (XMPPException ex) {
						System.err.println("Login failed.");
						System.err.println(ex);
					}
				} catch (XMPPException ex) {
					System.err.println("User account creation failed due to: ");
					System.err.println(ex);
				}
			}
		} catch (XMPPException e) {
			Throwable ex = e.getWrappedThrowable();
			ex.printStackTrace(System.err);
		}
    }

	@Override
	synchronized public void init() {
        if(!sendWorker.isAlive())
            sendWorker.start();
	}

    private ConnectionListener mConnListener = new ConnectionListener() {
            public void connectionClosed() {
                System.out.println("Connection closed");
            }

            public void connectionClosedOnError(Exception e) {
                System.out.println("Connection closed on error: " + e);
            }

            public void reconnectingIn(int i) {
                System.out.println("Reconnecting in: " + i);
            }

            public void reconnectionFailed(Exception e) {
                System.out.println("Reconnection failed: " + e);
            }

            public void reconnectionSuccessful() {
                System.out.println("Reconnection successful");
            }
        };

    private PacketListener mPacketListener = new PacketListener() {
            public void processPacket(final Packet p) {
                System.out.println("Processing " + p);
                final Message m = (Message) p;
                final String body = m.getBody();
                final String jid = m.getFrom();


                String id = mFormat.getMessagePersonId(body);
                if (!(jid.startsWith(id))) {
                    System.err.println("WTF! person id in message does not match sender!.");
                    return;
                }
                PublicKey pubKey = identity().publicKeyForPersonId(id);
                if (pubKey == null) {
                    System.err.println("WTF! message from unrecognized sender! " + id);
                    return;
                }

                try{
                    final String contents = mFormat.prepareIncomingMessage(body, pubKey);
                    int i = jid.indexOf("@");
                    final String from = i > -1 ? jid.substring(0, i) : jid;
                    signalMessageReceived(
                        new IncomingMessage() {
                            public String from() { return from; }
                            public String contents() { return contents; }
                            public String toString() { return contents(); }
                        });
                }
                catch(CryptoException e){
                    System.err.println("Failed in processing incoming message! Reason:");
                    e.printStackTrace(System.err);
                }
            }
        };

	private void addHandlers(XMPPConnection conn) {
		conn.addConnectionListener(mConnListener);
		conn.addPacketListener(mPacketListener, new PacketTypeFilter(Message.class));
	}

	private void removeHandlers(XMPPConnection conn) {
		conn.removeConnectionListener(mConnListener);
		conn.removePacketListener(mPacketListener);
	}

	private boolean connected() {
		return (mConnection != null) && mConnection.isConnected();
	}

	private boolean connectedToInternet() {
		return connectionStatus().isConnected();
	}

	private void assertConnected() {
		if (!connected()) {
			throw new IllegalStateException("Not connected!");
		}
	}

	@Override
	public void sendMessage(OutgoingMessage m) {
		mSendQ.offer(m);
	}
}
