package org.rssys.bench;

import org.openjdk.jmh.annotations.*;
import org.openjdk.jmh.infra.Blackhole;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.signature.PrivateKeyParameters;
import org.rssys.gost.signature.PublicKeyParameters;
import org.rssys.gost.tls13.TlsTestHelper;
import org.rssys.gost.tls13.cert.TlsCertificate;
import org.rssys.gost.tls13.cert.TlsCertificateValidator;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;

@BenchmarkMode(Mode.Throughput)
@OutputTimeUnit(TimeUnit.SECONDS)
@State(Scope.Benchmark)
public class CertValidationBench {

    private List<TlsCertificate> chain3;
    private List<TlsCertificate> chain2;
    private PublicKeyParameters caKey;

    @Setup(Level.Trial)
    public void setup() throws Exception {
        ECParameters params = ECParameters.tc26a256();
        // Root CA
        TlsTestHelper.CertBundle root = TlsTestHelper.createRootCA(params);
        caKey = root.cert.getPublicKey();

        // Intermediate CA, signed by root
        TlsTestHelper.CertBundle intCA = TlsTestHelper.createCertSignedBy(
                params, root.priv, root.cert.getPublicKey(), root.subjectDn,
                "240501120000Z", "290501120000Z",
                null, null, null, true, null);
        // Leaf cert, signed by intermediate
        TlsTestHelper.CertBundle leaf = TlsTestHelper.createCertSignedBy(
                params, intCA.priv, intCA.cert.getPublicKey(), intCA.subjectDn,
                "240501120000Z", "290501120000Z",
                new String[]{"example.com"}, null, new byte[]{(byte) 0x80},
                new String[]{"1.3.6.1.5.5.7.3.1"}, false, null);

        chain3 = new ArrayList<>();
        chain3.add(leaf.cert);
        chain3.add(intCA.cert);
        chain3.add(root.cert);

        chain2 = new ArrayList<>();
        chain2.add(leaf.cert);
        chain2.add(intCA.cert);
    }

    @Benchmark
    public void chainOnly(Blackhole bh) throws Exception {
        TlsCertificateValidator.checkServerCertificateChain(
                chain2, null, false, caKey);
    }

    @Benchmark
    public void chainWithHostname(Blackhole bh) throws Exception {
        TlsCertificateValidator.checkServerCertificateChain(
                chain2, "example.com", false, caKey);
    }
}
