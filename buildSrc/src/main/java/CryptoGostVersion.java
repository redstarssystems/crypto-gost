import org.gradle.api.GradleException;
import org.gradle.api.Project;

import javax.xml.parsers.DocumentBuilderFactory;
import java.io.File;

public class CryptoGostVersion {
    public static String resolve(Project project) {
        File dir = project.getProjectDir();
        while (dir != null) {
            File pom = new File(dir, "pom.xml");
            if (pom.exists()) {
                try {
                    var doc = DocumentBuilderFactory.newInstance()
                            .newDocumentBuilder().parse(pom);
                    var nodes = doc.getElementsByTagName("revision");
                    if (nodes.getLength() > 0) {
                        return nodes.item(0).getTextContent().trim();
                    }
                } catch (Exception e) {
                    throw new GradleException(
                            "Ошибка чтения <revision> из " + pom, e);
                }
            }
            dir = dir.getParentFile();
        }
        throw new GradleException(
                "Не найден корневой pom.xml с <revision> начиная от "
                        + project.getProjectDir());
    }
}
