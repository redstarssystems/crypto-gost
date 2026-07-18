import org.gradle.api.GradleException;
import org.gradle.api.Project;

import javax.xml.parsers.DocumentBuilderFactory;
import java.io.File;

public class GpgKeyName {
    public static String resolve(Project project) {
        File dir = project.getProjectDir();
        while (dir != null) {
            File pom = new File(dir, "pom.xml");
            if (pom.exists()) {
                try {
                    var doc = DocumentBuilderFactory.newInstance()
                            .newDocumentBuilder().parse(pom);
                    var profiles = doc.getElementsByTagName("profile");
                    for (int i = 0; i < profiles.getLength(); i++) {
                        var profile = profiles.item(i);
                        var children = profile.getChildNodes();
                        String id = null;
                        for (int j = 0; j < children.getLength(); j++) {
                            var c = children.item(j);
                            if ("id".equals(c.getNodeName())) {
                                id = c.getTextContent().trim();
                            }
                        }
                        if ("sign".equals(id)) {
                            var keynames = doc.getElementsByTagName("keyname");
                            if (keynames.getLength() > 0) {
                                return keynames.item(0).getTextContent().trim();
                            }
                        }
                    }
                } catch (Exception e) {
                    throw new GradleException(
                            "Ошибка чтения GPG keyname из профиля sign в pom.xml", e);
                }
            }
            dir = dir.getParentFile();
        }
        throw new GradleException(
                "GPG keyname не найден в профиле sign корневого pom.xml");
    }
}
