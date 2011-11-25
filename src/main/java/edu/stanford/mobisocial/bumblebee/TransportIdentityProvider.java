package edu.stanford.mobisocial.bumblebee;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;

import mobisocial.socialkit.User;

public interface TransportIdentityProvider {
	public PublicKey userPublicKey();
	public PrivateKey userPrivateKey();
	public String userPersonId();
	public PublicKey publicKeyForPersonId(String id);
	public String personIdForPublicKey(RSAPublicKey key);
	public User userForPersonId(String id);
}
