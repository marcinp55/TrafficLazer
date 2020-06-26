package com.marcin.pawlicki.trafficlazer;

import com.marcin.pawlicki.trafficlazer.sniffer.BasicSniffer;
import org.junit.Before;
import org.junit.Test;
import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.TcpPacket;
import org.pcap4j.packet.namednumber.TcpPort;

public class SecurityTest {
    private BasicSniffer basicSniffer;

    @Before
    public void setup() {
        basicSniffer = new BasicSniffer();
    }

    @Test
    public void shouldDetectSYNScan() throws PcapNativeException, NotOpenException {
        basicSniffer.findDeviceToCaptureFrom();
        basicSniffer.openHandle();
        PcapHandle sendHandle = basicSniffer.getNetworkInterface().openLive(basicSniffer.getSnapshotLength(), PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, basicSniffer.getReadTimeout());

        TcpPacket.Builder tcpPacketBuilder = new TcpPacket.Builder();

        Packet tcpTestPacket = tcpPacketBuilder
                .srcPort(new TcpPort((short) 23334, "TestPort1"))
                .dstPort(new TcpPort((short) 22222, "TestPort2"))
                .build();

        basicSniffer.capturePackets();

/*        System.out.println("YYY SENDING PACKET");
        sendHandle.sendPacket(tcpTestPacket);*/
    }
}
