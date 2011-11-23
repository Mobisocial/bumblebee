package mobisocial.socialkit;

import java.util.List;

public interface EncodedObj {

    public User getSender();
    public List<User> getRecipients();

    public String getEncodingType();
    public byte[] getEncodedObj();
    public byte[] getSignature();
}
