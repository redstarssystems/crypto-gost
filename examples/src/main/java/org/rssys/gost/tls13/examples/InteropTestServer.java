package org.rssys.gost.tls13.examples;

import org.rssys.gost.api.KeyGenerator;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.signature.PrivateKeyParameters;
import org.rssys.gost.signature.PublicKeyParameters;
import org.rssys.gost.tls13.TlsCiphersuite;
import org.rssys.gost.tls13.TlsSession;
import org.rssys.gost.tls13.cert.TlsCertificate;
import org.rssys.gost.tls13.config.TlsServerConfig;
import org.rssys.gost.tls13.transport.SocketTlsTransport;

import java.io.ByteArrayOutputStream;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.util.*;

public final class InteropTestServer {

    private InteropTestServer() {}

    public static void main(String[] args) throws Exception {
        int port = 8443;
        for (int i = 0; i < args.length; i++) {
            if ("--port".equals(args[i])) {
                port = Integer.parseInt(args[++i]);
            }
        }

        String localIp = detectLocalIp();
        ECParameters params = ECParameters.tc26a256();
        org.rssys.gost.api.KeyPair kp = KeyGenerator.generateKeyPair(params);
        PrivateKeyParameters priv = kp.getPrivate();
        PublicKeyParameters pub = kp.getPublic();

        byte[] subjectDn = ExampleUtils.buildDN("Interop Test Server");
        byte[] sanExt = ExampleUtils.buildSanExt(null, new String[]{localIp});
        byte[] kuExt = ExampleUtils.buildKeyUsageExt(new byte[]{(byte) 0x80});
        byte[] ekuExt = ExampleUtils.buildEkuExt("1.3.6.1.5.5.7.3.1");
        ByteArrayOutputStream extBuf = new ByteArrayOutputStream();
        extBuf.write(sanExt); extBuf.write(kuExt); extBuf.write(ekuExt);
        byte[] combinedExts = extBuf.toByteArray();

        byte[] tbs = ExampleUtils.buildTbs(pub, params, subjectDn, subjectDn, combinedExts);
        byte[] hash = ExampleUtils.doHash(tbs, params.hlen);
        byte[] sig = org.rssys.gost.api.Signature.signHash(hash, priv);
        byte[] certDer = ExampleUtils.derSequence(tbs, ExampleUtils.buildAlgId(params), ExampleUtils.derBitString(sig));
        TlsCertificate serverCert = new TlsCertificate(certDer);

        TlsCiphersuite suite = TlsCiphersuite.byId(0xC103);
        System.out.println("=== Interop Test Server ===");
        System.out.println("Listening on " + localIp + ":" + port);
        System.out.println("Cipher: KUZNYECHIK_MGM_L (0xC103)");
        System.out.println("Cert: CN=Interop Test Server, SAN=IP:" + localIp);
        System.out.println("Cert self-signed (accept browser warning)");
        System.out.println("URL: https://" + localIp + ":" + port + "/");
        System.out.println("Waiting for connection...");

        try (ServerSocket ss = new ServerSocket(port)) {
            try (Socket socket = ss.accept()) {
                System.out.println("Accepted: " + socket.getRemoteSocketAddress());
                socket.setSoTimeout(15000);
                SocketTlsTransport transport = new SocketTlsTransport(socket);
                TlsServerConfig config = new TlsServerConfig(transport, suite, serverCert, priv);
                TlsSession server = TlsSession.createServer(config);
                server.handshakeAsServer();

                System.out.println("Handshake OK");
                System.out.println("Negotiated: 0x" + Integer.toHexString(server.getCipherSuite().getId()));
                System.out.println("Peer certs: "
                        + (server.getPeerCertificates() != null ? server.getPeerCertificates().size() : 0));
                System.out.println("SNI: " + server.getRequestedServerName());

                byte[] req = server.read();
                System.out.println("Received " + req.length + " bytes from client");

                byte[] resp = ("HTTP/1.1 200 OK\r\n"
                        + "Content-Type: text/plain\r\n"
                        + "Content-Length: 10\r\n"
                        + "Connection: close\r\n"
                        + "\r\n"
                        + "INTEROP_OK").getBytes("UTF-8");
                server.write(resp);
                System.out.println("Response sent: INTEROP_OK");

                try { server.close(); } catch (Exception ignored) {}
            }
        }

        System.out.println("=== Interop test complete ===");
    }

    private static String detectLocalIp() throws SocketException {
        Enumeration<NetworkInterface> nis = NetworkInterface.getNetworkInterfaces();
        while (nis.hasMoreElements()) {
            NetworkInterface ni = nis.nextElement();
            if (ni.isLoopback() || !ni.isUp()) continue;
            Enumeration<InetAddress> addrs = ni.getInetAddresses();
            while (addrs.hasMoreElements()) {
                InetAddress addr = addrs.nextElement();
                if (addr instanceof Inet4Address) {
                    return addr.getHostAddress();
                }
            }
        }
        return "127.0.0.1";
    }
}
