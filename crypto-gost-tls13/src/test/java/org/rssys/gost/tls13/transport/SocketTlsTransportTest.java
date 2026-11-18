package org.rssys.gost.tls13.transport;

import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.IOException;
import java.io.PipedInputStream;
import java.io.PipedOutputStream;
import java.net.Socket;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.tls13.TlsConstants;

/** Транспорт поверх сокета: границы длины записи. */
@DisplayName("SocketTlsTransport: границы длины записи")
class SocketTlsTransportTest {

    @Test
    @DisplayName("SocketTlsTransport: запись > 16640 -> IOException")
    void recordLongerThanMaximumIsRejected() throws Exception {
        PipedInputStream pipeIn = new PipedInputStream();
        PipedOutputStream pipeOut = new PipedOutputStream(pipeIn);
        Socket fakeSocket =
                new Socket() {
                    @Override
                    public java.io.InputStream getInputStream() {
                        return pipeIn;
                    }

                    @Override
                    public java.io.OutputStream getOutputStream() {
                        return pipeOut;
                    }

                    @Override
                    public void close() {}
                };

        byte[] header = new byte[TlsConstants.RECORD_HEADER_SIZE];
        header[0] = TlsConstants.CT_APPLICATION_DATA;
        header[1] = TlsConstants.LEGACY_VERSION_MAJOR;
        header[2] = TlsConstants.LEGACY_VERSION_MINOR;
        header[3] = (byte) (20000 >>> 8);
        header[4] = (byte) 20000;
        pipeOut.write(header);
        pipeOut.flush();

        SocketTlsTransport st = new SocketTlsTransport(fakeSocket);
        assertThrows(IOException.class, st::receiveRecord);
    }
}
