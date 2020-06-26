package com.marcin.pawlicki.trafficlazer.repository;

import org.pcap4j.packet.Packet;

import java.util.ArrayList;
import java.util.List;

/**
 * This is a mock of a repository used as a temporary storage in Java collections only.
 */
public class BasicRepository {
    private static BasicRepository repositoryInstance;
    private final List<Packet> singleRunCapturedPackets = new ArrayList<>();

    private BasicRepository() {
    }

    public static synchronized BasicRepository getInstance() {
        if (repositoryInstance == null) {
            repositoryInstance = new BasicRepository();
        }

        return repositoryInstance;
    }

    public void addToSingleRunCapturedPackets(Packet packet) {
        singleRunCapturedPackets.add(packet);
    }

    public List<Packet> getSingleRunCapturedPackets() {
        return singleRunCapturedPackets;
    }
}
