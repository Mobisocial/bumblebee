package mobisocial.socialkit;

import java.util.List;

/**
 * An obj that has been prepared for transmission, containing
 * details such as the sending user, originating application, etc.
 */
public interface PreparedObj extends Obj {

    /**
     * The application identified with the creation of this Obj.
     */
    public String getAppId();

    /**
     * Returns the {@link User} sending this obj.
     * @return
     */
    public User getSender();

    /**
     * A list of the intended recipients for this obj.
     */
    public List<User> getRecipients();

    /**
     * A user maintains a local sequence number indicating how many messages
     * he has sent to the feed given by {@link #getFeedName()}
     */
    public long getSequenceNumber();

    /**
     * The feed to which this obj will be sent.
     * @return
     */
    public String getFeedName();

    /**
     * The user-local timestamp indicating when this obj was created.
     */
    public long getTimestamp();
}