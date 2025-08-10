package org.gluu.agama.update;

import io.jans.as.common.model.common.User;
import io.jans.as.common.service.common.EncryptionService;
import io.jans.as.common.service.common.UserService;
import io.jans.orm.exception.operation.EntryNotFoundException;
import io.jans.service.cdi.util.CdiUtil;
import io.jans.util.StringHelper;

import org.gluu.agama.user.UsernameUpdate;
import io.jans.agama.engine.script.LogUtils;
import java.io.IOException;
import io.jans.as.common.service.common.ConfigurationService;
import java.security.SecureRandom;
import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import java.util.regex.Pattern;
import org.gluu.agama.smtp.SendEmailTemplate;
import org.gluu.agama.smtp.jans.model.ContextData;
import io.jans.model.SmtpConfiguration;
import io.jans.service.MailService;
import io.jans.as.model.common.IntrospectionResponse;
import io.jans.as.server.service.IntrospectionService;

public class JansUsernameUpdate extends UsernameUpdate {

    private static final String MAIL = "mail";
    private static final String UID = "uid";
    private static final String DISPLAY_NAME = "displayName";
    private static final String GIVEN_NAME = "givenName";
    private static final String LAST_NAME = "sn";
    private static final String PASSWORD = "userPassword";
    private static final String INUM_ATTR = "inum";
    private static final String EXT_ATTR = "jansExtUid";
    private static final String USER_STATUS = "jansStatus";
    private static final String EXT_UID_PREFIX = "github:";
    private static final String LANG = "lang";
    private static final SecureRandom RAND = new SecureRandom();

    private static JansUsernameUpdate INSTANCE = null;

    public JansUsernameUpdate() {
    }

    public static synchronized JansUsernameUpdate getInstance() {
        if (INSTANCE == null)
            INSTANCE = new JansUsernameUpdate();

        return INSTANCE;
    }

    public static Map<String, Object> validateBearerToken(String access_token) {
        Map<String, Object> result = new HashMap<>();
        
        try {
            LogUtils.log("validateBearerToken called");
            LogUtils.log("access_token parameter received: " + (access_token != null ? "not null" : "null"));
            
            if (access_token != null) {
                LogUtils.log("access_token length: " + access_token.length());
                LogUtils.log("access_token first 30 chars: " + access_token.substring(0, Math.min(30, access_token.length())) + "...");
            }
            
            // Check if token is missing or empty
            if (access_token == null || access_token.trim().isEmpty()) {
                LogUtils.log("ERROR: Access token is missing or empty");
                result.put("valid", false);
                result.put("error", "Access token is missing. Please provide it in the request body.");
                return result;
            }
            
            String token = access_token.trim();
            LogUtils.log("Starting token introspection...");
            
            // Get IntrospectionService
            IntrospectionService introspectionService = CdiUtil.bean(IntrospectionService.class);
            
            if (introspectionService == null) {
                LogUtils.log("ERROR: IntrospectionService is null");
                result.put("valid", false);
                result.put("error", "IntrospectionService not available");
                return result;
            }
            
            // Introspect the token
            LogUtils.log("Calling introspection service...");
            IntrospectionResponse introspectionResponse = introspectionService.introspect(token);
            
            if (introspectionResponse == null) {
                LogUtils.log("ERROR: Introspection response is null");
                result.put("valid", false);
                result.put("error", "Token validation failed - introspection returned null");
                return result;
            }
            
            LogUtils.log("Introspection response received. Active: " + introspectionResponse.isActive());
            
            if (!introspectionResponse.isActive()) {
                LogUtils.log("ERROR: Token is not active/expired");
                result.put("valid", false);
                result.put("error", "Token is invalid or expired");
                return result;
            }
            
            // Check scopes
            String scopes = introspectionResponse.getScope();
            LogUtils.log("Token scopes: " + scopes);
            
            boolean hasRequiredScope = scopes != null && (
                scopes.contains("profile") ||
                scopes.contains("user_update") ||
                scopes.contains("openid")
            );
            
            if (!hasRequiredScope) {
                LogUtils.log("ERROR: Token does not have required scope. Has: " + scopes);
                result.put("valid", false);
                result.put("error", "Token does not have required scope (profile, user_update, or openid)");
                return result;
            }
            
            // Token is valid
            String clientId = introspectionResponse.getClientId();
            String username = introspectionResponse.getUsername();
            
            LogUtils.log("Token validation SUCCESSFUL!");
            LogUtils.log("Client ID: " + clientId);
            LogUtils.log("Username: " + username);
            
            result.put("valid", true);
            result.put("clientId", clientId);
            result.put("username", username);
            result.put("scopes", scopes);
            
        } catch (Exception e) {
            LogUtils.log("ERROR: Exception in validateBearerToken: " + e.getMessage());
            e.printStackTrace();
            result.put("valid", false);
            result.put("error", "Token validation error: " + e.getMessage());
        }
        
        return result;
    }
    
    public boolean passwordPolicyMatch(String userPassword) {
        String regex = "^(?=.*[!@#$^&*])[A-Za-z0-9!@#$^&*]{6,}$";
        Pattern pattern = Pattern.compile(regex);
        return pattern.matcher(userPassword).matches();
    }

    public boolean usernamePolicyMatch(String userName) {
        String regex = "^[A-Za-z]+$";
        Pattern pattern = Pattern.compile(regex);
        return pattern.matcher(userName).matches();
    }

    public Map<String, String> getUserEntityByMail(String email) {
        User user = getUser(MAIL, email);
        boolean local = user != null;
        LogUtils.log("There is % local account for %", local ? "a" : "no", email);

        if (local) {
            String uid = getSingleValuedAttr(user, UID);
            String inum = getSingleValuedAttr(user, INUM_ATTR);
            String name = getSingleValuedAttr(user, GIVEN_NAME);

            if (name == null) {
                name = getSingleValuedAttr(user, DISPLAY_NAME);
                if (name == null && email != null && email.contains("@")) {
                    name = email.substring(0, email.indexOf("@"));
                }
            }

            Map<String, String> userMap = new HashMap<>();
            userMap.put(UID, uid);
            userMap.put(INUM_ATTR, inum);
            userMap.put("name", name);
            userMap.put("email", email);

            return userMap;
        }

        return new HashMap<>();
    }

    public Map<String, String> getUserEntityByUsername(String username) {
        User user = getUser(UID, username);
        boolean local = user != null;
        LogUtils.log("There is % local account for %", local ? "a" : "no", username);

        if (local) {
            String email = getSingleValuedAttr(user, MAIL);
            String inum = getSingleValuedAttr(user, INUM_ATTR);
            String name = getSingleValuedAttr(user, GIVEN_NAME);
            String uid = getSingleValuedAttr(user, UID);
            String displayName = getSingleValuedAttr(user, DISPLAY_NAME);
            String givenName = getSingleValuedAttr(user, GIVEN_NAME);
            String sn = getSingleValuedAttr(user, LAST_NAME);
            String lang = getSingleValuedAttr(user, LANG);

            if (name == null) {
                name = getSingleValuedAttr(user, DISPLAY_NAME);
                if (name == null && email != null && email.contains("@")) {
                    name = email.substring(0, email.indexOf("@"));
                }
            }
            
            Map<String, String> userMap = new HashMap<>();
            userMap.put(UID, uid);
            userMap.put(INUM_ATTR, inum);
            userMap.put("name", name);
            userMap.put("email", email);
            userMap.put(DISPLAY_NAME, displayName);
            userMap.put(LAST_NAME, sn);
            userMap.put(LANG, lang);
            userMap.put("empty", "false");

            return userMap;
        }

        Map<String, String> emptyMap = new HashMap<>();
        emptyMap.put("empty", "true");
        return emptyMap;
    }

    public String addNewUser(Map<String, String> profile) throws Exception {
        Set<String> attributes = Set.of("uid", "mail", "displayName", "givenName", "sn", "userPassword");
        User user = new User();

        attributes.forEach(attr -> {
            String val = profile.get(attr);
            if (StringHelper.isNotEmpty(val)) {
                user.setAttribute(attr, val);
            }
        });

        UserService userService = CdiUtil.bean(UserService.class);
        user = userService.addUser(user, true);

        if (user == null) {
            throw new EntryNotFoundException("Added user not found");
        }

        return getSingleValuedAttr(user, INUM_ATTR);
    }

    public String updateUser(Map<String, String> profile) throws Exception {
        String inum = profile.get(INUM_ATTR);
        User user = getUser(INUM_ATTR, inum);

        if (user == null) {
            throw new EntryNotFoundException("User not found for inum: " + inum);
        }

        String currentEmail = getSingleValuedAttr(user, MAIL);
        String currentLanguage = getSingleValuedAttr(user, LANG);

        String newUid = profile.get(UID);
        if (StringHelper.isNotEmpty(newUid)) {
            user.setAttribute(UID, newUid);
            user.setUserId(newUid);
        }

        if (StringHelper.isNotEmpty(currentEmail)) {
            user.setAttribute(MAIL, currentEmail);
        }
        if (StringHelper.isNotEmpty(currentLanguage)) {
            user.setAttribute(LANG, currentLanguage);
        }

        UserService userService = CdiUtil.bean(UserService.class);
        user = userService.updateUser(user);

        if (user == null) {
            throw new EntryNotFoundException("Updated user not found");
        }

        return getSingleValuedAttr(user, INUM_ATTR);
    }

    public Map<String, String> getUserEntityByInum(String inum) {
        User user = getUser(INUM_ATTR, inum);
        boolean local = user != null;
        LogUtils.log("There is % local account for %", local ? "a" : "no", inum);

        if (local) {
            String email = getSingleValuedAttr(user, MAIL);
            String name = getSingleValuedAttr(user, GIVEN_NAME);
            String uid = getSingleValuedAttr(user, UID);
            String displayName = getSingleValuedAttr(user, DISPLAY_NAME);
            String givenName = getSingleValuedAttr(user, GIVEN_NAME);
            String sn = getSingleValuedAttr(user, LAST_NAME);
            String userPassword = getSingleValuedAttr(user, PASSWORD);
            String lang = getSingleValuedAttr(user, LANG);

            if (name == null) {
                name = getSingleValuedAttr(user, DISPLAY_NAME);
                if (name == null && email != null && email.contains("@")) {
                    name = email.substring(0, email.indexOf("@"));
                }
            }
            
            Map<String, String> userMap = new HashMap<>();
            userMap.put(UID, uid);
            userMap.put("userId", uid);
            userMap.put(INUM_ATTR, inum);
            userMap.put("name", name);
            userMap.put("email", email);
            userMap.put(DISPLAY_NAME, displayName);
            userMap.put(LAST_NAME, sn);
            userMap.put(PASSWORD, userPassword);
            userMap.put(LANG, lang);

            return userMap;
        }

        return new HashMap<>();
    }

    private String getSingleValuedAttr(User user, String attribute) {
        Object value = null;
        if (attribute.equals(UID)) {
            value = user.getUserId();
        } else {
            value = user.getAttribute(attribute, true, false);
        }
        return value == null ? null : value.toString();
    }

    private User getUser(String attributeName, String value) {
        UserService userService = CdiUtil.bean(UserService.class);
        return userService.getUserByAttribute(attributeName, value, true);
    }

    public boolean sendUsernameUpdateEmail(String to, String newUsername, String lang) {
        try {
            ConfigurationService configService = CdiUtil.bean(ConfigurationService.class);
            SmtpConfiguration smtpConfig = configService.getConfiguration().getSmtpConfiguration();

            if (smtpConfig == null) {
                LogUtils.log("SMTP configuration is missing.");
                return false;
            }

            String preferredLang = (lang != null && !lang.isEmpty()) ? lang.toLowerCase() : "en";

            Map<String, Map<String, String>> translations = new HashMap<>();
            translations.put("en", Map.of(
                    "subject", "Your username has been updated successfully",
                    "body", "Your username has been updated to",
                    "footer", "Thanks for keeping your account secure."));
            translations.put("es", Map.of(
                    "subject", "Su nombre de usuario se ha actualizado correctamente",
                    "body", "Su nombre de usuario se ha actualizado a",
                    "footer", "Gracias por mantener su cuenta segura."));
            translations.put("fr", Map.of(
                    "subject", "Votre nom d'utilisateur a été mis à jour avec succès",
                    "body", "Votre nom d'utilisateur a été mis à jour en",
                    "footer", "Merci de garder votre compte sécurisé."));

            Map<String, String> bundle = translations.getOrDefault(preferredLang, translations.get("en"));

            ContextData context = new ContextData();
            context.setDevice("Unknown");
            context.setLocation("Unknown");
            context.setTimeZone("UTC");

            String htmlBody = SendEmailTemplate.get(newUsername, context, bundle);
            String subject = bundle.get("subject");
            String textBody = bundle.get("body") + ": " + newUsername;

            MailService mailService = CdiUtil.bean(MailService.class);
            boolean sent = mailService.sendMailSigned(
                    smtpConfig.getFromEmailAddress(),
                    smtpConfig.getFromName(),
                    to,
                    null,
                    subject,
                    textBody,
                    htmlBody);

            LogUtils.log("Username update email sent to %", to);
            return sent;
        } catch (Exception e) {
            LogUtils.log("Failed to send username update email: %", e.getMessage());
            return false;
        }
    }

    private SmtpConfiguration getSmtpConfiguration() {
        ConfigurationService configurationService = CdiUtil.bean(ConfigurationService.class);
        return configurationService.getConfiguration().getSmtpConfiguration();
    }
}