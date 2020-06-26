package com.marcin.pawlicki.trafficlazer.listener;

import com.marcin.pawlicki.trafficlazer.repository.BasicRepository;
import com.marcin.pawlicki.trafficlazer.sniffer.BasicSniffer;
import org.pcap4j.core.PacketListener;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.packet.Packet;

public class BasicPacketListener implements PacketListener {
    private PcapHandle pcapHandle;

    public BasicPacketListener(PcapHandle pcapHandle) {
        this.pcapHandle = pcapHandle;
    }

    @Override
    public void gotPacket(Packet packet) {
        BasicRepository.getInstance().addToSingleRunCapturedPackets(packet);
    }

    public PcapHandle getPcapHandle() {
        return pcapHandle;
    }

    public void setPcapHandle(PcapHandle pcapHandle) {
        this.pcapHandle = pcapHandle;
    }
}
