package com.antigravity.blipper.desktop.network;

import com.antigravity.blipper.desktop.security.SessionStateRegistry;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetSocketAddress;
import java.net.SocketException;
import java.nio.charset.StandardCharsets;
import java.util.Map;

public class UdpDiscoveryResponder implements AutoCloseable {

    public static final String DISCOVERY_MAGIC = "BLIPPER_DISCOVER_V1";

    private final SessionStateRegistry sessionRegistry;
    private final ObjectMapper mapper = new ObjectMapper();
    private volatile DatagramSocket socket;
    private volatile Thread workerThread;

    public UdpDiscoveryResponder(SessionStateRegistry sessionRegistry) {
        this.sessionRegistry = sessionRegistry;
    }

    public synchronized int start(int udpPort, int advertisedTlsPort, String serverCertSha256Hex) {
        stop();
        try {
            DatagramSocket ds = new DatagramSocket(null);
            ds.setReuseAddress(true);
            ds.bind(new InetSocketAddress("0.0.0.0", udpPort));
            this.socket = ds;
            int boundPort = ds.getLocalPort();

            byte[] responseBytes = mapper.writeValueAsString(Map.of(
                    "proto", "blipper-v1",
                    "port", advertisedTlsPort,
                    "serverCertSha256", serverCertSha256Hex
            )).getBytes(StandardCharsets.UTF_8);

            Thread t = new Thread(() -> runLoop(ds, responseBytes), "blipper-udp-discovery");
            t.setDaemon(true);
            this.workerThread = t;
            t.start();
            return boundPort;
        } catch (Exception e) {
            stop();
            throw new IllegalStateException("Failed to start 60s UDP discovery responder", e);
        }
    }

    private void runLoop(DatagramSocket ds, byte[] responseBytes) {
        byte[] buf = new byte[256];
        while (!ds.isClosed()) {
            try {
                if (sessionRegistry.getState() != SessionStateRegistry.State.PAIRING_WINDOW
                        || sessionRegistry.isPairingExpired(System.currentTimeMillis())) {
                    stop();
                    return;
                }
                DatagramPacket pkt = new DatagramPacket(buf, buf.length);
                ds.receive(pkt);

                if (sessionRegistry.getState() != SessionStateRegistry.State.PAIRING_WINDOW
                        || sessionRegistry.isPairingExpired(System.currentTimeMillis())) {
                    stop();
                    return;
                }
                String msg = new String(pkt.getData(), pkt.getOffset(), pkt.getLength(), StandardCharsets.UTF_8).trim();
                if (DISCOVERY_MAGIC.equals(msg)) {
                    DatagramPacket reply = new DatagramPacket(
                            responseBytes,
                            responseBytes.length,
                            pkt.getAddress(),
                            pkt.getPort()
                    );
                    ds.send(reply);
                }
            } catch (SocketException closed) {
                return;
            } catch (Exception ignored) {
                // Ignore malformed UDP datagrams silently
            }
        }
    }

    public synchronized void stop() {
        DatagramSocket ds = this.socket;
        this.socket = null;
        if (ds != null && !ds.isClosed()) {
            ds.close();
        }
        Thread t = this.workerThread;
        this.workerThread = null;
        if (t != null) {
            t.interrupt();
        }
    }

    public boolean isRunning() {
        DatagramSocket ds = this.socket;
        return ds != null && !ds.isClosed();
    }

    @Override
    public void close() {
        stop();
    }
}
