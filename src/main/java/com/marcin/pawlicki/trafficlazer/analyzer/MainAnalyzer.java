package com.marcin.pawlicki.trafficlazer.analyzer;

import com.marcin.pawlicki.trafficlazer.repository.BasicRepository;
import org.pcap4j.packet.EthernetPacket;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.TcpPacket;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class MainAnalyzer {
    private boolean isSYNScan = false;
    private boolean isARPSpoofing = false;

    public void findSecurityRisks(List<Packet> packetsToAnalyze) {
        isSYNScan = checkForSYNScan(packetsToAnalyze);
        isARPSpoofing = checkForARPSpoofing(packetsToAnalyze);
    }

    private boolean checkForSYNScan(List<Packet> packetsToAnalyze) {
        List<IpV4Packet> ipV4SYNPackets = new ArrayList<>();
        Map<String, List<Packet>> synSourcesMap = new HashMap<>();
        int numberOfSingleSourceSYNBeforeAlert = 5;

        // Filter SYN packets and extract IPv4 and TCP packets
        for (Packet packet : packetsToAnalyze) {
            if (packet.toString().contains("SYN: true")) {
                ipV4SYNPackets.add(packet.get(IpV4Packet.class));
            }
        }

        for (IpV4Packet ipV4Packet : ipV4SYNPackets) {
            TcpPacket tcpPacket = ipV4Packet.get(TcpPacket.class);

            String sourceAddress = ipV4Packet.getHeader().getSrcAddr().toString();
            String sourcePort = tcpPacket.getHeader().getSrcPort().toString();

            String mapKey = sourceAddress.concat("-").concat(sourcePort);

            synSourcesMap.computeIfAbsent(mapKey, k -> new ArrayList<>());

            synSourcesMap.get(mapKey).add(ipV4Packet);
        }

        // Check if number of single source SYN packets is bigger than limit and detect attack
        for (Map.Entry<String, List<Packet>> synSource : synSourcesMap.entrySet()) {
            if (synSource.getValue().size() > numberOfSingleSourceSYNBeforeAlert) {
                BasicRepository.getInstance().getDangerousPackets().addAll(synSource.getValue());

                return true;
            }
        }

        return false;
    }

    private boolean checkForARPSpoofing(List<Packet> packetsToAnalyze) {
        List<Packet> listOfARPRequests = new ArrayList<>();

        // Filter ARP requests
        for (Packet packet : packetsToAnalyze) {
            if (packet.toString().contains(("ARP Header")) && packet.toString().contains("REQUEST")) {
                listOfARPRequests.add(packet);
            }
        }

        // Check if any of requests is not a broadcast
        for (Packet packet : listOfARPRequests) {
            EthernetPacket ethernetPacket = packet.get(EthernetPacket.class);

            if (!ethernetPacket.getHeader().getDstAddr().toString().equals("ff:ff:ff:ff:ff:ff")) {
                BasicRepository.getInstance().addToDangerousPackets(packet);

                return true;
            }
        }

        return false;
    }

    public boolean isSYNScan() {
        return isSYNScan;
    }

    public boolean isARPSpoofing() {
        return isARPSpoofing;
    }
}
