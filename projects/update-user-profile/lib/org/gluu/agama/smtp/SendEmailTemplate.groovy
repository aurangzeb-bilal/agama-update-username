package org.gluu.agama.smtp;

import java.time.*;
import java.time.format.DateTimeFormatter;
import java.util.Map;
import org.gluu.agama.smtp.jans.model.ContextData;

class SendEmailTemplate {

    private static DateTimeFormatter formatter = DateTimeFormatter.ofPattern("MMMM dd, YYYY, hh:mma (O)");

    static String get(String username, ContextData context, Map<String, String> bundle) {
        return """
<div style="width: 640px; font-size: 18px; font-family: 'Roboto', sans-serif; font-weight: 300; color: #333;">


    <!-- Main Content -->
    <div style="padding: 20px; border-bottom: 1px solid #ccc;">
        <p><b>Hi,</b><br><br>
        """ + bundle.get("body") + """</p>

        <div style="display: flex; justify-content: center; margin: 20px 0;">
            <div style="background-color: #B29163; color: white; font-size: 30px; font-weight: 500; padding: 10px 20px; border-radius: 8px;" align="center">
                """ + username + """
            </div>
        </div>

        <p style="font-size: 14px;">
            """ + bundle.get("footer") + """
        </p>
    </div>

    <!-- Date Section -->
    <div style="padding: 12px; background-color: #ecf0f5; font-size: 16px;">
        <p style="color: #48596b; font-weight: 500;">""" + bundle.getOrDefault("dateLabel", "When this happened:") + """</p>
        <p><span style="color: #48596b; font-weight: 500;">Date:</span><br>""" + computeDateTime(context.getTimeZone()) + """</p>
    </div>

    <!-- Contact Us Section -->
    <div style="background-color: #f9f9f9; padding: 20px; font-size: 14px; display: flex; justify-content: space-between; align-items: flex-start;">
        <div style="flex: 1;">
            <img src="https://phiwallet.com/components/images/logo.png" alt="Phi Logo" style="height: 40px;">
            <p style="margin: 8px 0;">NIPC: 516547186<br>Gold dealer license: T7164</p>
        </div>
        <div style="flex: 1;">
            <p style="font-weight: bold; margin-bottom: 5px;">""" + bundle.getOrDefault("contactTitle", "Get in touch") + """</p>
            <p>📱 +351 308 802 610<br>
               📱 +34 518 89 80 81<br>
               ✉️ <a href="mailto:support@phiwallet.com" style="color:#333;">support@phiwallet.com</a><br>
               📍 Avenida da Liberdade 262, R/C esquerdo, Lisbon 1250-149, Portugal</p>
        </div>
    </div>
</div>
        """;
    }

    private static String computeDateTime(String zone) {
        Instant now = Instant.now();
        try {
            return now.atZone(ZoneId.of(zone)).format(formatter);
        } catch (Exception e) {
            return now.atOffset(ZoneOffset.UTC).format(formatter);
        }
    }
}
