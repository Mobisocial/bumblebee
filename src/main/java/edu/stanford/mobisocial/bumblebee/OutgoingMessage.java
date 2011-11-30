package edu.stanford.mobisocial.bumblebee;
import mobisocial.socialkit.PreparedObj;

public interface OutgoingMessage {
	public PreparedObj contents();
	public void onEncoded(byte[] encoded);
	public byte[] getEncoded();
	public void onCommitted();
	public long getLocalUniqueId();
	
}
