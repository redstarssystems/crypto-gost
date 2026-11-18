package org.rssys.gost.crossval.util;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;

/** Поддельное хранилище {@code uRoot} для проверки логики сессии без КриптоПро. */
final class FakeRootStore implements RootStore {

    private record Cert(byte[] keyId, byte[] der) {}

    final List<String> calls = new ArrayList<>();
    private final List<Cert> certs = new ArrayList<>();
    // Если задан, install кладёт в хранилище этот DER вместо переданного (сбой постусловия)
    byte[] derStoredByInstall;
    // Если задан, install кладёт сертификат и затем падает (сбой после начала установки)
    boolean failAfterInstall;

    void put(byte[] keyId, byte[] der) {
        certs.add(new Cert(keyId.clone(), der.clone()));
    }

    int size() {
        return certs.size();
    }

    boolean mutated() {
        return calls.stream().anyMatch(c -> c.startsWith("install") || c.startsWith("delete"));
    }

    private List<Cert> matching(byte[] keyId) {
        return certs.stream().filter(c -> Arrays.equals(c.keyId(), keyId)).toList();
    }

    @Override
    public int countByKeyId(byte[] keyId) {
        calls.add("count");
        return matching(keyId).size();
    }

    @Override
    public byte[] exportByKeyId(byte[] keyId) {
        calls.add("export");
        List<Cert> found = matching(keyId);
        if (found.size() != 1) {
            throw new IllegalStateException("export of " + found.size() + " certificates");
        }
        return found.get(0).der().clone();
    }

    @Override
    public void install(byte[] der) throws IOException {
        calls.add("install");
        byte[] stored = derStoredByInstall != null ? derStoredByInstall : der;
        // keyid в поддельном хранилище задаётся первым байтом DER: достаточно для проверки логики
        certs.add(new Cert(new byte[] {stored[0]}, stored.clone()));
        if (failAfterInstall) {
            throw new IOException("certmgr install failed after the certificate was added");
        }
    }

    @Override
    public void deleteByKeyId(byte[] keyId) {
        calls.add("delete");
        certs.removeIf(c -> Arrays.equals(c.keyId(), keyId));
    }

    @Override
    public String describeByKeyId(byte[] keyId) {
        return "listing " + HexFormat.of().formatHex(keyId);
    }
}
