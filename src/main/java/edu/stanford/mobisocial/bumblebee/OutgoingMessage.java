package edu.stanford.mobisocial.bumblebee;
import mobisocial.socialkit.EncodedObj;
import mobisocial.socialkit.PreparedObj;

public interface OutgoingMessage {
	public PreparedObj contents();
	public void onEncoded(EncodedObj encoded);
	public EncodedObj getEncoded();
	public void onCommitted();
	public long getLocalUniqueId();
	
}
