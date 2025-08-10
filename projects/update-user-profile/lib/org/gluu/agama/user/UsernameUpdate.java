package org.gluu.agama.user;

import java.util.Map;
import org.gluu.agama.update.JansUsernameUpdate;



public abstract class UsernameUpdate {
    public abstract String addNewUser(Map<String, String> profile) throws Exception;

    public abstract boolean usernamePolicyMatch(String userName);

    public abstract boolean passwordPolicyMatch(String userPassword);

    public abstract String updateUser(Map<String, String> profile) throws Exception;

    public abstract Map<String, String> getUserEntityByInum(String inum);

    public abstract boolean sendUsernameUpdateEmail(String to, String newUsername, String lang);

    public static UsernameUpdate getInstance(){
        return  JansUsernameUpdate.getInstance();
    }    
}
