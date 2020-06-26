package com.marcin.pawlicki.trafficlazer.analyzer;

import org.pcap4j.packet.Packet;

import java.util.List;

public class MainAnalyzer {
    private boolean isSYNScan = false;

    public List<Packet> findSecurityRisks(List<Packet> packetsToAnalyze) {
        isSYNScan = checkForSYNScan(packetsToAnalyze);

        return null;
    }

    private boolean checkForSYNScan(List<Packet> packetsToAnalyze) {
        for (Packet packet : packetsToAnalyze) {

        }

        return false;
    }
}
