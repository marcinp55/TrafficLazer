package com.marcin.pawlicki.trafficlazer.simulator;

import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.packet.*;
import org.pcap4j.packet.namednumber.*;
import org.pcap4j.util.ByteArrays;
import org.pcap4j.util.IpV4Helper;
import org.pcap4j.util.MacAddress;

import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.UnknownHostException;

public class AttackSimulator {
    private final PcapHandle pcapSendHandle;
    private final int maximumTransmissionUnit;
    private final String packetsSourceAddress;

    public AttackSimulator(PcapHandle pcapSendHandle, int maximumTransmissionUnit, String packetsSourceAddress) {
        this.pcapSendHandle = pcapSendHandle;
        this.maximumTransmissionUnit = maximumTransmissionUnit;
        this.packetsSourceAddress = packetsSourceAddress;
    }

    public void simulateSynScan() {
        TcpPacket.Builder tcpPacketBuilder = new TcpPacket.Builder();
        IpV4Packet.Builder ipV4PacketBuilder = new IpV4Packet.Builder();
        EthernetPacket.Builder ethernetPacketBuilder = new EthernetPacket.Builder();

        int packetsToGenerate = 10;

        for (int i = 0; i <= packetsToGenerate - 1; i++) {
            int destinationPortNumber = 22000 + i;

            try {
                tcpPacketBuilder
                        .srcPort(new TcpPort((short) 21212, "TestSourcePort"))
                        .dstPort(new TcpPort((short) destinationPortNumber, "TestDestinationPort"))
                        .srcAddr(InetAddress.getByName(packetsSourceAddress))
                        .dstAddr(InetAddress.getByName("64.13.134.52"))
                        .syn(true)
                        .correctLengthAtBuild(true)
                        .correctChecksumAtBuild(true);
            } catch (UnknownHostException e) {
                System.out.println("Exception occurred when building TCP packet.");
                e.printStackTrace();
            }

            try {
                ipV4PacketBuilder
                        .version(IpVersion.IPV4)
                        .tos(IpV4Rfc791Tos.newInstance((byte) 0))
                        .ttl((byte) 100)
                        .protocol(IpNumber.TCP)
                        .srcAddr((Inet4Address) InetAddress.getByName(packetsSourceAddress))
                        .dstAddr((Inet4Address) InetAddress.getByName("64.13.134.52"))
                        .payloadBuilder(tcpPacketBuilder)
                        .correctChecksumAtBuild(true)
                        .correctLengthAtBuild(true);
            } catch (UnknownHostException e) {
                System.out.println("Exception occurred when building IPv4 packet.");
                e.printStackTrace();
            }

            ethernetPacketBuilder
                    .dstAddr(MacAddress.getByName("12:34:56:ab:cd:ef"))
                    .srcAddr(MacAddress.getByName("C0-E4-34-27-90-0F"))
                    .type(EtherType.IPV4)
                    .paddingAtBuild(true);

            for (final Packet ipV4Packet : IpV4Helper.fragment(ipV4PacketBuilder.build(), maximumTransmissionUnit)) {
                ethernetPacketBuilder.payloadBuilder(
                        new AbstractPacket.AbstractBuilder() {
                            @Override
                            public Packet build() {
                                return ipV4Packet;
                            }
                        }
                );

                Packet ethernetPacket = ethernetPacketBuilder.build();

                try {
                    pcapSendHandle.sendPacket(ethernetPacket);
                } catch (PcapNativeException | NotOpenException e) {
                    System.out.println("Exception occurred while sending packet.");
                    e.printStackTrace();
                }
            }
        }
    }

    public void simulateARPSpoofing() {
        ArpPacket.Builder arpPacketBuilder = new ArpPacket.Builder();
        EthernetPacket.Builder ethernetPacketBuilder = new EthernetPacket.Builder();

        try {
            arpPacketBuilder
                    .hardwareType(ArpHardwareType.ETHERNET)
                    .protocolType(EtherType.IPV4)
                    .hardwareAddrLength((byte) MacAddress.SIZE_IN_BYTES)
                    .protocolAddrLength((byte) ByteArrays.INET4_ADDRESS_SIZE_IN_BYTES)
                    .operation(ArpOperation.REQUEST)
                    .srcHardwareAddr(MacAddress.getByName("fe:01:01:02:02:04"))
                    .srcProtocolAddr(InetAddress.getByName("192.0.5.17"))
                    .dstHardwareAddr(MacAddress.ETHER_BROADCAST_ADDRESS)
                    .dstProtocolAddr(InetAddress.getByName("192.1.5.10"));
        } catch (UnknownHostException e) {
            System.out.println("Exception occurred while creating ARP packet.");
            e.printStackTrace();
        }

        ethernetPacketBuilder
                .dstAddr(MacAddress.getByName("fe:00:01:02:03:04")) // Not broadcast
                .srcAddr(MacAddress.getByName("fe:10:01:20:02:30"))
                .type(EtherType.ARP)
                .payloadBuilder(arpPacketBuilder)
                .paddingAtBuild(true);

        EthernetPacket arpPacketToSend = ethernetPacketBuilder.build();

        try {
            pcapSendHandle.sendPacket(arpPacketToSend);
        } catch (PcapNativeException | NotOpenException e) {
            System.out.println("Exception occurred while sending packet.");
            e.printStackTrace();
        }
    }
}
