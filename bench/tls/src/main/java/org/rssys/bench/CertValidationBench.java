package org.rssys.bench;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;
import org.openjdk.jmh.annotations.*;
import org.openjdk.jmh.infra.Blackhole;
import org.rssys.gost.pkix.cert.GostCertificate;
import org.rssys.gost.pkix.cert.PkixCertTestHelper;
import org.rssys.gost.pkix.cert.TrustAnchors;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.signature.PrivateKeyParameters;
import org.rssys.gost.signature.PublicKeyParameters;
import org.rssys.gost.tls13.cert.TlsCertificateValidator;
import org.rssys.gost.tls13.cert.TlsPeerPolicy;

@BenchmarkMode(Mode.Throughput)
@OutputTimeUnit(TimeUnit.SECONDS)
@State(Scope.Benchmark)
public class CertValidationBench {

    private List<GostCertificate> chain3;
    private List<GostCertificate> chain2;
    private PublicKeyParameters caKey;
    private TlsPeerPolicy policyNoHost;
    private TlsPeerPolicy policyWithHost;

    @Setup(Level.Trial)
    public void setup() throws Exception {
        ECParameters params = ECParameters.tc26a256();
        // Root CA
        PkixCertTestHelper.CertBundle root = PkixCertTestHelper.createRootCA(params);
        caKey = root.cert.getPublicKey();

        // Intermediate CA, signed by root
        PkixCertTestHelper.CertBundle intCA = PkixCertTestHelper.createCertSignedBy(
                params, root.priv, root.cert.getPublicKey(), root.subjectDn,
                "20240501120000Z", "21060101120000Z",
                null, null, null, true, null);
        // Leaf cert, signed by intermediate
        PkixCertTestHelper.CertBundle leaf = PkixCertTestHelper.createCertSignedBy(
                params, intCA.priv, intCA.cert.getPublicKey(), intCA.subjectDn,
                "20240501120000Z", "21060101120000Z",
                new String[]{"example.com"}, null, new byte[]{(byte) 0x80},
                new String[]{"1.3.6.1.5.5.7.3.1"}, false, null);

        chain3 = new ArrayList<>();
        chain3.add(leaf.cert);
        chain3.add(intCA.cert);
        chain3.add(root.cert);

        chain2 = new ArrayList<>();
        chain2.add(leaf.cert);
        chain2.add(intCA.cert);

        policyNoHost = TlsPeerPolicy.serverWithoutHostnameVerification(
                        TrustAnchors.ofCertificate(root.cert));
        policyWithHost = TlsPeerPolicy.server("example.com", TrustAnchors.ofCertificate(root.cert));
    }

    @Benchmark
    public void chainOnly(Blackhole bh) throws Exception {
        bh.consume(TlsCertificateValidator.validateStructure(chain2, policyNoHost));
    }

    @Benchmark
    public void chainWithHostname(Blackhole bh) throws Exception {
        bh.consume(TlsCertificateValidator.validateStructure(chain2, policyWithHost));
    }
}
