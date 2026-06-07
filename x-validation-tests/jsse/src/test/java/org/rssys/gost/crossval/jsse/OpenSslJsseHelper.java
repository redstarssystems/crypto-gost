package org.rssys.gost.crossval.jsse;

import org.rssys.gost.crossval.util.CrossValUtils;
import org.rssys.gost.crossval.util.OpenSslChecker;
import org.rssys.gost.jsse.bridge.CertificateBridge;
import org.rssys.gost.jsse.engine.GostSSLEngine;
import org.rssys.gost.jsse.manager.GostX509KeyManager;
import org.rssys.gost.jsse.manager.GostX509TrustManager;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.signature.PrivateKeyParameters;
import org.rssys.gost.signature.PublicKeyParameters;
import org.rssys.gost.tls13.TlsTestHelper;
import org.rssys.gost.tls13.cert.TlsCertificate;

import javax.net.ssl.SSLEngineResult;
import java.io.BufferedReader;
import java.io.EOFException;
import java.io.InputStreamReader;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.concurrent.TimeUnit;

final class OpenSslJsseHelper {

    private static final int MAX_CIPHERTEXT = 16640;
    private static final int MAX_PLAINTEXT = 16384;
    private static final int HANDSHAKE_MAX_ITERATIONS = 80;

    private OpenSslJsseHelper() {}

    static void assumeGostTls13() {
        OpenSslChecker.assumeGostTls13();
    }

    static String[] resolveTls13Flags() {
        return OpenSslChecker.resolveTls13Flags();
    }

    static int findFreePort() throws Exception {
        try (ServerSocket ss = new ServerSocket(0)) {
            return ss.getLocalPort();
        }
    }

    static Process startSClient(int port, String ciphersuite, String curves,
                                 String... extraArgs) throws Exception {
        String openssl = OpenSslChecker.resolveOpenSslBinary();
        String[] providerFlags = resolveTls13Flags();

        String[] cmd = CrossValUtils.concat(
                new String[]{openssl, "s_client", "-connect", "127.0.0.1:" + port,
                        "-tls1_3", "-ciphersuites", ciphersuite, "-curves", curves,
                        "-servername", "example.com", "-ign_eof"},
                providerFlags,
                extraArgs
        );

        return startProcess(cmd);
    }

    static String runSClientWithHttpGet(int port, String ciphersuite, String curves,
                                         long timeoutMs, String... extraArgs) throws Exception {
        Process client = startSClient(port, ciphersuite, curves, extraArgs);
        try {
            OutputStream stdin = client.getOutputStream();
            stdin.write("GET / HTTP/1.0\r\nHost: example.com\r\n\r\n".getBytes(StandardCharsets.UTF_8));
            stdin.flush();
            stdin.close();
            return readOutput(client, timeoutMs);
        } finally {
            destroyProcess(client);
        }
    }

    static String runSClientWithData(int port, String ciphersuite, String curves,
                                      byte[] data, long timeoutMs, String... extraArgs) throws Exception {
        Process client = startSClient(port, ciphersuite, curves, extraArgs);
        try {
            OutputStream stdin = client.getOutputStream();
            stdin.write(data);
            stdin.flush();
            stdin.close();
            return readOutput(client, timeoutMs);
        } finally {
            destroyProcess(client);
        }
    }

    static Process startSServer(int port, String ciphersuite, String curves,
                                 Path tmpDir) throws Exception {
        generateGostCert(tmpDir);
        return startSServer(port, ciphersuite, curves,
                tmpDir.resolve("cert.pem").toString(),
                tmpDir.resolve("key.pem").toString());
    }

    static Process startSServer(int port, String ciphersuite, String curves,
                                 String certPem, String keyPem,
                                 String... extraArgs) throws Exception {
        String openssl = OpenSslChecker.resolveOpenSslBinary();
        String[] providerFlags = resolveTls13Flags();

        String[] cmd = CrossValUtils.concat(
                new String[]{openssl, "s_server", "-accept", String.valueOf(port),
                        "-tls1_3", "-ciphersuites", ciphersuite, "-curves", curves,
                        "-cert", certPem, "-key", keyPem, "-www"},
                providerFlags,
                extraArgs
        );

        return startProcess(cmd);
    }

    private static Process startProcess(String[] cmd) throws Exception {
        ProcessBuilder pb = new ProcessBuilder(cmd);
        pb.redirectErrorStream(true);
        pb.environment().putAll(OpenSslChecker.getOpenSslEnv());
        return pb.start();
    }

    static boolean waitForString(Process process, String expected, long timeoutMs) throws Exception {
        long deadline = System.currentTimeMillis() + timeoutMs;
        BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
        while (System.currentTimeMillis() < deadline) {
            while (reader.ready()) {
                String line = reader.readLine();
                if (line != null && line.contains(expected)) return true;
            }
            if (!process.isAlive()) return false;
            Thread.sleep(50);
        }
        return false;
    }

    static String readOutput(Process process, long timeoutMs) throws Exception {
        if (!process.waitFor(timeoutMs, TimeUnit.MILLISECONDS)) {
            process.destroyForcibly();
            throw new RuntimeException("Process timed out after " + timeoutMs + "ms");
        }
        return new String(process.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
    }

    static void destroyProcess(Process process) {
        if (process != null) {
            process.destroyForcibly();
            try { process.waitFor(3, TimeUnit.SECONDS); } catch (InterruptedException ignored) {
                Thread.currentThread().interrupt();
            }
        }
    }

    record ServerPkiBundle(TlsCertificate cert, PrivateKeyParameters priv,
                           TlsCertificate caCert, PublicKeyParameters caPub) {}

    static ServerPkiBundle createServerPki(ECParameters params) throws Exception {
        TlsTestHelper.CertBundle rootCa = TlsTestHelper.createRootCA(params);
        PublicKeyParameters caPub = rootCa.cert.getPublicKey();

        TlsTestHelper.CertBundle serverCert = TlsTestHelper.createCertSignedBy(
                params, rootCa.priv, caPub, rootCa.subjectDn,
                "240501120000Z", "290501120000Z",
                new String[]{"localhost"}, new byte[]{(byte) 0x80}, null,
                false, null);

        return new ServerPkiBundle(
                serverCert.cert, serverCert.priv,
                rootCa.cert, caPub);
    }

    static GostX509KeyManager createKeyManager(TlsCertificate serverCert,
                                                TlsCertificate caCert,
                                                PrivateKeyParameters priv) throws Exception {
        X509Certificate[] jcaChain = CertificateBridge.toJcaChain(serverCert, caCert);
        GostX509KeyManager km = new GostX509KeyManager();
        km.addKeyEntry("default", jcaChain, priv);
        return km;
    }

    static GostX509TrustManager createTrustManager(PublicKeyParameters caPub) {
        if (caPub != null) {
            return new GostX509TrustManager(caPub, false);
        }
        return new GostX509TrustManager(null, false);
    }

    /* ========================================================================
     * Чтение полных TLS-записей из TCP (readTlsRecord)
     * SSLEngine handshake loop over TCP
     * ======================================================================== */

    private static void readFully(InputStream in, byte[] buf, int off, int len) throws Exception {
        while (len > 0) {
            int n = in.read(buf, off, len);
            if (n == -1) throw new EOFException("Connection closed");
            off += n;
            len -= n;
        }
    }

    private static ByteBuffer readTlsRecord(InputStream in) throws Exception {
        byte[] hdr = new byte[5];
        readFully(in, hdr, 0, 5);
        int len = ((hdr[3] & 0xFF) << 8) | (hdr[4] & 0xFF);
        byte[] record = new byte[5 + len];
        System.arraycopy(hdr, 0, record, 0, 5);
        readFully(in, record, 5, len);
        return ByteBuffer.wrap(record);
    }

    static void doEngineHandshakeOverTcp(GostSSLEngine engine,
                                          Socket socket) throws Exception {
        InputStream sockIn = socket.getInputStream();
        OutputStream sockOut = socket.getOutputStream();
        ByteBuffer appBuf = ByteBuffer.allocate(MAX_PLAINTEXT);

        for (int i = 0; i < HANDSHAKE_MAX_ITERATIONS; i++) {
            SSLEngineResult.HandshakeStatus hs = engine.getHandshakeStatus();
            if (hs == SSLEngineResult.HandshakeStatus.FINISHED
                    || hs == SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING) return;

            switch (hs) {
                case NEED_WRAP: {
                    ByteBuffer net = ByteBuffer.allocate(MAX_CIPHERTEXT + 64);
                    engine.wrap(ByteBuffer.allocate(0), net);
                    net.flip();
                    byte[] data = new byte[net.remaining()];
                    net.get(data);
                    sockOut.write(data);
                    sockOut.flush();
                    break;
                }
                case NEED_UNWRAP: {
                    ByteBuffer record = readTlsRecord(sockIn);
                    appBuf.clear();
                    engine.unwrap(record, appBuf);
                    break;
                }
                case NEED_TASK: {
                    Runnable task = engine.getDelegatedTask();
                    if (task != null) task.run();
                    break;
                }
            }
        }
        throw new RuntimeException("Рукопожатие engine не завершилось за "
                + HANDSHAKE_MAX_ITERATIONS + " итераций, status="
                + engine.getHandshakeStatus());
    }

    static byte[] sendAppDataAndReceiveOverTcp(GostSSLEngine engine,
                                                 byte[] dataToSend,
                                                 Socket socket) throws Exception {
        InputStream sockIn = socket.getInputStream();
        OutputStream sockOut = socket.getOutputStream();
        ByteBuffer appBuf = ByteBuffer.allocate(MAX_PLAINTEXT);

        ByteBuffer net = ByteBuffer.allocate(MAX_CIPHERTEXT + 64);
        engine.wrap(ByteBuffer.wrap(dataToSend), net);
        net.flip();
        byte[] sendData = new byte[net.remaining()];
        net.get(sendData);
        sockOut.write(sendData);
        sockOut.flush();

        for (int i = 0; i < HANDSHAKE_MAX_ITERATIONS; i++) {
            ByteBuffer record = readTlsRecord(sockIn);
            appBuf.clear();
            SSLEngineResult result = engine.unwrap(record, appBuf);
            if (result.bytesProduced() > 0) {
                appBuf.flip();
                byte[] response = new byte[appBuf.remaining()];
                appBuf.get(response);
                return response;
            }
        }
        throw new RuntimeException("Нет данных от пира после отправки");
    }

    /* ========================================================================
     * OpenSSL certificate generation helpers
     * ======================================================================== */

    static void generateGostCert(Path tmpDir) throws Exception {
        generateGostCert(tmpDir, "gost2012_256", "A");
    }

    static void generateGostCert(Path tmpDir, String algo, String paramset) throws Exception {
        Path keyDer = tmpDir.resolve("key.der");
        Path keyPem = tmpDir.resolve("key.pem");
        Path certPem = tmpDir.resolve("cert.pem");
        String[] flags = resolveTls13Flags();

        OpenSslChecker.exec(CrossValUtils.concat(
                new String[]{OpenSslChecker.resolveOpenSslBinary(), "genpkey"},
                flags,
                new String[]{"-algorithm", algo,
                        "-pkeyopt", "paramset:" + paramset,
                        "-outform", "DER",
                        "-out", keyDer.toString()}));

        OpenSslChecker.exec(CrossValUtils.concat(
                new String[]{OpenSslChecker.resolveOpenSslBinary(), "pkey"},
                flags,
                new String[]{"-in", keyDer.toString(), "-inform", "DER",
                        "-out", keyPem.toString()}));

        OpenSslChecker.exec(CrossValUtils.concat(
                new String[]{OpenSslChecker.resolveOpenSslBinary(), "req", "-new", "-x509"},
                flags,
                new String[]{"-key", keyPem.toString(),
                        "-out", certPem.toString(),
                        "-subj", "/CN=TestServer",
                        "-days", "365",
                        "-config", "/dev/null"}));
    }

    static String privateKeyToPem(byte[] der) {
        String b64 = Base64.getMimeEncoder(64, new byte[]{'\n'}).encodeToString(der);
        return "-----BEGIN PRIVATE KEY-----\n" + b64 + "\n-----END PRIVATE KEY-----\n";
    }
}
