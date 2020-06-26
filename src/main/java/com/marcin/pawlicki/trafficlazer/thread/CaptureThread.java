package com.marcin.pawlicki.trafficlazer.thread;

import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PacketListener;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;

public class CaptureThread implements Runnable {
    private final PcapHandle handle;
    private final PacketListener listener;

    public CaptureThread(PcapHandle handle, PacketListener listener) {
        this.handle = handle;
        this.listener = listener;
    }

    @Override
    public void run() {
        try {
            handle.loop(-1, listener);
        } catch (PcapNativeException | NotOpenException | InterruptedException e) {
            e.printStackTrace();
        }
    }
}
