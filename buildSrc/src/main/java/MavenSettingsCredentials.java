import org.gradle.api.GradleException;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import javax.xml.parsers.DocumentBuilderFactory;
import java.io.File;

public class MavenSettingsCredentials {
    public static MavenCredentials resolve(String serverId) {
        File settingsFile = new File(
                System.getProperty("user.home") + "/.m2/settings.xml");
        if (!settingsFile.exists()) {
            throw new GradleException(
                    "~/.m2/settings.xml не найден. Настрой credentials для сервера "
                            + serverId + ".");
        }
        try {
            var doc = DocumentBuilderFactory.newInstance()
                    .newDocumentBuilder().parse(settingsFile);
            var servers = doc.getElementsByTagName("server");
            for (int i = 0; i < servers.getLength(); i++) {
                Element s = (Element) servers.item(i);
                Node child = s.getFirstChild();
                String id = null, username = null, password = null;
                while (child != null) {
                    if (child.getNodeType() == Node.ELEMENT_NODE) {
                        switch (child.getNodeName()) {
                            case "id" -> id = child.getTextContent().trim();
                            case "username" -> username = child.getTextContent().trim();
                            case "password" -> password = child.getTextContent().trim();
                        }
                    }
                    child = child.getNextSibling();
                }
                if (serverId.equals(id) && username != null && password != null) {
                    return new MavenCredentials(username, password);
                }
            }
        } catch (Exception e) {
            throw new GradleException(
                    "Ошибка чтения ~/.m2/settings.xml", e);
        }
        throw new GradleException(
                "Сервер с id=" + serverId + " не найден в ~/.m2/settings.xml");
    }

    public static class MavenCredentials {
        private final String username;
        private final String password;

        public MavenCredentials(String username, String password) {
            this.username = username;
            this.password = password;
        }

        public String getUsername() { return username; }
        public String getPassword() { return password; }
    }
}
