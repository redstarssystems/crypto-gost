package org.rssys.gost.tls13.examples;

import org.rssys.gost.tls13.TlsCiphersuite;
import org.rssys.gost.tls13.TlsConstants;
import org.rssys.gost.tls13.TlsSession;
import org.rssys.gost.signature.PrivateKeyParameters;
import org.rssys.gost.tls13.cert.Pkcs12Loader;
import org.rssys.gost.tls13.cert.TlsCertificate;
import org.rssys.gost.tls13.config.TlsServerConfig;
import org.rssys.gost.tls13.transport.SocketTlsTransport;

import java.io.FileInputStream;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.List;

/**
 * Standalone echo-сервер для ручного interop-тестирования.
 * <p>
 * Принимает одно TLS-соединение, эхом возвращает полученные данные,
 * затем закрывает соединение.
 * <p>
 * Пример запуска:
 * {@snippet :
 * java org.rssys.gost.tls13.examples.TlsEchoServer \
 *     --port 4443 \
 *     --cert /path/to/server.p12 \
 *     --password changeit \
 *     --cipher L
 *}
 * <p>
 * Флаг {@code --mtls} включает запрос клиентского сертификата.
 * Флаг {@code --ca} указывает ключ CA (только для mTLS).
 */
public final class TlsEchoServer {

    private TlsEchoServer() {}

    public static void main(String[] args) throws Exception {
        int port = 4443;
        String p12Path = null;
        String password = "changeit";
        TlsCiphersuite suite = TlsCiphersuite.byId(TlsConstants.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L);
        boolean mtls = false;
        String caPath = null;
        String caPassword = null;

        for (int i = 0; i < args.length; i++) {
            switch (args[i]) {
                case "--port":
                    port = Integer.parseInt(args[++i]);
                    break;
                case "--cert":
                    p12Path = args[++i];
                    break;
                case "--password":
                    password = args[++i];
                    break;
                case "--cipher": {
                    String name = args[++i].toUpperCase();
                    if (name.equals("L")) {
                        suite = TlsCiphersuite.byId(TlsConstants.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L);
                    } else if (name.equals("S")) {
                        suite = TlsCiphersuite.byId(TlsConstants.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_S);
                    } else {
                        System.err.println("Unknown cipher: " + name + " (use L or S)");
                        System.exit(1);
                    }
                    break;
                }
                case "--mtls":
                    mtls = true;
                    break;
                case "--ca":
                    caPath = args[++i];
                    caPassword = args[++i];
                    break;
                default:
                    System.err.println("Unknown flag: " + args[i]);
                    System.exit(1);
            }
        }

        if (p12Path == null) {
            System.err.println("Usage: TlsEchoServer --cert <p12> [--port <port>] [--password <pwd>]"
                    + " [--cipher L|S] [--mtls] [--ca <p12> <password>]");
            System.exit(1);
        }

        Pkcs12Loader.Result p12;
        try (FileInputStream fis = new FileInputStream(p12Path)) {
            p12 = Pkcs12Loader.load(fis.readAllBytes(), password.toCharArray());
        }

        List<TlsCertificate> chain = p12.getCertificateChain();
        PrivateKeyParameters privKey = p12.getPrivateKey();
        TlsServerConfig config = new TlsServerConfig(suite, chain, privKey);

        if (mtls && caPath != null) {
            try (FileInputStream fis = new FileInputStream(caPath)) {
                Pkcs12Loader.Result caP12 = Pkcs12Loader.load(fis.readAllBytes(), caPassword.toCharArray());
                config.withCaPublicKey(caP12.getCertificateChain().get(0).getPublicKey());
            }
        }

        try (ServerSocket ss = new ServerSocket(port)) {
            System.out.println("Listening on port " + port + " (0x" + Integer.toHexString(suite.getId()) + ", mtls=" + mtls + ")");

            try (Socket socket = ss.accept()) {
                System.out.println("Accepted: " + socket.getRemoteSocketAddress());
                TlsServerConfig connConfig = new TlsServerConfig(suite, chain, privKey);
                if (mtls && caPath != null) {
                    connConfig.withCaPublicKey(config.getCaPublicKey());
                }
                try (SocketTlsTransport transport = new SocketTlsTransport(socket);
                     TlsSession server = TlsSession.createServer(connConfig, transport)) {
                    server.handshakeAsServer();
                    System.out.println("Handshake done: 0x" + Integer.toHexString(suite.getId())
                            + ", peer=" + (server.getPeerCertificates() != null
                            ? server.getPeerCertificates().size() + " certs" : "none"));

                    byte[] data = server.read();
                    System.out.println("Received " + data.length + " bytes");
                    server.write(data);
                    System.out.println("Echoed " + data.length + " bytes");
                    System.out.println("Connection closed");
                }
            }
        }
    }
}
