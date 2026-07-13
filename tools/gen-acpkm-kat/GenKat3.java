import java.nio.file.*;
import java.util.*;
import java.math.BigInteger;
import org.rssys.gost.jca.spec.GostDerCodec;
import org.rssys.gost.pkix.cert.GostCertificate;
import org.rssys.gost.pkix.cms.*;
import org.rssys.gost.cipher.*;
import org.rssys.gost.cipher.mode.*;
import org.rssys.gost.signature.PrivateKeyParameters;
import org.rssys.gost.signature.PublicKeyParameters;
import org.rssys.gost.api.KeyAgreement;
import org.rssys.gost.util.DerCodec;

public class GenKat3 {
    static final String SSL = "/usr/bin/openssl";
    
    static final long NON_OMAC_BASE = 0xCAFE0000L;  // 3403661312
    static final long OMAC_BASE     = 0xBEEF0000L;  // 3202342912
    
    public static void main(String[] args) throws Exception {
        String outDir = args[0];
        Path t = Files.createTempDirectory("kat3-");
        try {
            run(SSL, "genpkey", "-engine", "gost", "-algorithm", "gost2012_256",
                    "-pkeyopt", "paramset:XA", "-out", t.resolve("k.pem").toString());
            run(SSL, "req", "-engine", "gost", "-new", "-x509", "-key", t.resolve("k.pem").toString(),
                    "-md_gost12_256", "-subj", "/CN=K", "-days", "1", "-out", t.resolve("c.pem").toString());
            run(SSL, "x509", "-in", t.resolve("c.pem").toString(), "-outform", "DER", "-out", t.resolve("c.der").toString());
            run(SSL, "pkey", "-engine", "gost", "-in", t.resolve("k.pem").toString(), "-outform", "DER", "-out", t.resolve("k.der").toString());
            GostCertificate cert = GostCertificate.fromPemOrDer(Files.readAllBytes(t.resolve("c.der")));
            PrivateKeyParameters priv = GostDerCodec.decodePrivateKey(Files.readAllBytes(t.resolve("k.der")));
            
            generate(t, cert, priv, outDir, 524288, NON_OMAC_BASE, false, "non-omac");
            generate(t, cert, priv, outDir, 262144, OMAC_BASE, true, "omac-a");
            generate(t, cert, priv, outDir, 262140, OMAC_BASE, true, "omac-b");
        } finally {
            Files.walk(t).sorted(Comparator.reverseOrder()).forEach(p -> { try{Files.delete(p);}catch(Exception e){} });
        }
    }
    
    static void generate(Path t, GostCertificate cert, PrivateKeyParameters priv, String outDir,
                         int len, long base, boolean omac, String tag) throws Exception {
        byte[] plain = new byte[len];
        new Random(base + len).nextBytes(plain);
        Files.write(t.resolve("p.bin"), plain);
        
        String cf = omac ? "-kuznyechik-ctr-acpkm-omac" : "-kuznyechik-ctr-acpkm";
        run(SSL, "cms", "-engine", "gost", "-encrypt", "-binary", cf,
                "-in", t.resolve("p.bin").toString(), "-outform", "DER", "-out", t.resolve("e.p7e").toString(),
                t.resolve("c.pem").toString());
        byte[] env = Files.readAllBytes(t.resolve("e.p7e"));
        
        byte[] dec = CmsEnvelopedDataDecryptor.decrypt(env, priv, cert, new Kexp15CmsKeyWrap());
        if (!Arrays.equals(plain, dec)) throw new RuntimeException(tag + " roundtrip FAILED");
        
        byte[][] v = extractCekUkmEnc(env, priv, cert);
        byte[] cek = v[0], ukm = v[1], encCont = v[2];
        
        if (!omac) {
            byte[] our = CtrAcpkmMode.encryptOnly(new SymmetricKey(cek), ukm, plain, AcpkmSectionSize.CMS);
            if (!Arrays.equals(encCont, our)) {
                int d = diff(encCont, our);
                throw new RuntimeException(tag + " enc mismatch at " + d + ": encCont["+d+"]=" + (encCont[d]&0xFF) + " our["+d+"]=" + (our[d]&0xFF));
            }
        } else {
            CmsOmacHelper.EncryptResult r = CmsOmacHelper.encrypt(plain, cek, ukm);
            if (!Arrays.equals(encCont, r.encryptedContent())) {
                int d = diff(encCont, r.encryptedContent());
                throw new RuntimeException(tag + " omac enc mismatch at " + d);
            }
            CmsOmacHelper.decrypt(encCont, r.macAttribute().encodedMac(), cek, ukm);
        }
        
        Files.write(Path.of(outDir, tag + ".cek"), cek);
        Files.write(Path.of(outDir, tag + ".ukm"), ukm);
        Files.write(Path.of(outDir, tag + ".ct"), encCont);
        Files.write(Path.of(outDir, tag + ".ptlen"), String.valueOf(len).getBytes());
        Files.write(Path.of(outDir, tag + ".seed"), String.valueOf(base + len).getBytes());
        System.out.println(tag + " OK (pt=" + len + ", ct=" + encCont.length + ", seed=" + (base + len) + ")");
    }
    
    static int diff(byte[] a, byte[] b) {
        for (int i = 0; i < Math.min(a.length, b.length); i++) if (a[i] != b[i]) return i;
        return -1;
    }
    
    static byte[][] extractCekUkmEnc(byte[] env, PrivateKeyParameters priv, GostCertificate cert) throws Exception {
        CmsContentInfo ci = CmsContentInfo.decode(env);
        byte[][] ep = DerCodec.parseSequenceContents(ci.content(), 0);
        byte[] eci = ep[2];
        byte[][] eciParts = DerCodec.parseSequenceContents(eci, 0);
        byte[][] algParts = DerCodec.parseSequenceContents(eciParts[1], 0);
        byte[][] ivSeq = DerCodec.parseSequenceContents(algParts[1], 0);
        byte[] ukm = DerCodec.parseOctetString(ivSeq[0], 0);
        
        byte[] encCont;
        int ecTag = eciParts[2][0] & 0xFF;
        if (ecTag == DerCodec.TAG_CTX_PRIMITIVE_0) {
            int[] el = DerCodec.decodeLength(eciParts[2], 1);
            encCont = Arrays.copyOfRange(eciParts[2], 1 + el[1], 1 + el[1] + el[0]);
        } else {
            encCont = DerCodec.collectImplicitOctets(eciParts[2], 0);
        }
        
        byte[] ris = ep[1];
        byte[][] ra = DerCodec.parseSetContents(ris, 0);
        BigInteger mySer = cert.getSerialNumberBigInt();
        byte[] myIss = cert.getIssuerDnBytes();
        byte[] cek = null;
        
        for (byte[] ri : ra) {
            if ((ri[0] & 0xFF) != 0x30) continue;
            byte[][] kt = DerCodec.parseSequenceContents(ri, 0);
            CmsIssuerAndSerialNumber rid = CmsIssuerAndSerialNumber.decode(kt[1]);
            if (!rid.serial().equals(mySer) || !Arrays.equals(rid.issuer(), myIss)) continue;
            
            byte[] encKeyDer = DerCodec.parseOctetString(kt[3], 0);
            byte[][] gkt = DerCodec.parseSequenceContents(encKeyDer, 0);
            byte[] wrappedCek = DerCodec.parseOctetString(gkt[0], 0);
            byte[][] spkiParts = DerCodec.parseSequenceContents(gkt[1], 0);
            byte[] spkiEnc = DerCodec.encodeSequence(spkiParts[0], spkiParts[1]);
            PublicKeyParameters ephPub = GostDerCodec.decodePublicKey(spkiEnc);
            byte[] ukmBytes = DerCodec.parseOctetString(gkt[2], 0);
            byte[] iv = Arrays.copyOfRange(ukmBytes, 24, 32);
            BigInteger ukmBi = Kexp15CmsKeyWrap.kegVkoUkm(ukmBytes);
            byte[] kek = KeyAgreement.vkoGostR3410_2012_256(priv, ephPub, ukmBi);
            try {
                cek = new Kexp15CmsKeyWrap().unwrap(wrappedCek, kek, ukmBytes, iv);
            } finally { Arrays.fill(kek, (byte)0); }
            break;
        }
        if (cek == null) throw new RuntimeException("CEK not extracted");
        return new byte[][]{cek, ukm, encCont};
    }
    
    static void run(String... cmd) throws Exception {
        Process p = new ProcessBuilder(cmd).redirectErrorStream(true).start();
        String o = new String(p.getInputStream().readAllBytes());
        if (p.waitFor() != 0) throw new RuntimeException(cmd[0] + ": " + o);
    }
}
