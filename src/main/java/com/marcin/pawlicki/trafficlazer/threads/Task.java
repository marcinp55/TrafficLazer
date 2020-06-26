package com.marcin.pawlicki.trafficlazer.threads;

import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PacketListener;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;

public class Task implements Runnable {
    private PcapHandle handle;
    private PacketListener listener;

    public Task(PcapHandle handle, PacketListener listener) {
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
