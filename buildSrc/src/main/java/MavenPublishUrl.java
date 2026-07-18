import org.gradle.api.GradleException;
import org.gradle.api.Project;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import javax.xml.parsers.DocumentBuilderFactory;
import java.io.File;

public class MavenPublishUrl {
    public static String resolve(Project project) {
        boolean isSnapshot = CryptoGostVersion.resolve(project).endsWith("-SNAPSHOT");
        File dir = project.getProjectDir();
        while (dir != null) {
            File pom = new File(dir, "pom.xml");
            if (pom.exists()) {
                try {
                    var doc = DocumentBuilderFactory.newInstance()
                            .newDocumentBuilder().parse(pom);
                    Element root = doc.getDocumentElement();
                    Element distMgmt = getChildElement(root, "distributionManagement");
                    if (distMgmt != null) {
                        String tag = isSnapshot ? "snapshotRepository" : "repository";
                        Element repo = getChildElement(distMgmt, tag);
                        if (repo == null) {
                            repo = getChildElement(distMgmt, "repository");
                        }
                        if (repo != null) {
                            String url = getChildText(repo, "url");
                            if (url != null) return url;
                        }
                    }
                } catch (Exception e) {
                    throw new GradleException(
                            "Ошибка чтения distributionManagement из " + pom, e);
                }
            }
            dir = dir.getParentFile();
        }
        throw new GradleException(
                "URL репозитория не найден в distributionManagement корневого pom.xml");
    }

    private static Element getChildElement(Element parent, String name) {
        Node child = parent.getFirstChild();
        while (child != null) {
            if (child.getNodeType() == Node.ELEMENT_NODE
                    && child.getNodeName().equals(name))
                return (Element) child;
            child = child.getNextSibling();
        }
        return null;
    }

    private static String getChildText(Element parent, String name) {
        Element el = getChildElement(parent, name);
        return el != null ? el.getTextContent().trim() : null;
    }
}
