package com.marcin.pawlicki.trafficlazer.reporter;

import com.marcin.pawlicki.trafficlazer.analyzer.MainAnalyzer;
import com.marcin.pawlicki.trafficlazer.repository.BasicRepository;

public class BasicReporter {
    public void reportFoundIssues(MainAnalyzer analyzer) {
        String securityReport = "Scanning found following security issues: " +
                "\n SYN Scanning: " + analyzer.isSYNScan() +
                "\n ARP Spoofing: " + analyzer.isARPSpoofing() +
                "\n ------------------------------------------" +
                "\n Packets to check for security risks: \n" +
                BasicRepository.getInstance().getDangerousPackets();

        System.out.println(securityReport);
    }
}
