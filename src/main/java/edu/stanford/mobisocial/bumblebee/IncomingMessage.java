package edu.stanford.mobisocial.bumblebee;

import mobisocial.socialkit.SignedObj;

public interface IncomingMessage {
	public String from();
	public SignedObj contents();
	public long hash();
}
