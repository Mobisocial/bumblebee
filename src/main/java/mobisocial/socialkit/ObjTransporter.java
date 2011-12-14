package mobisocial.socialkit;

import java.util.Set;

public interface ObjTransporter {

    public boolean transportObjSync(User recipient, EncodedObj obj);
    public Set<User> transportObjSync(Set<User> users, EncodedObj obj);
}
