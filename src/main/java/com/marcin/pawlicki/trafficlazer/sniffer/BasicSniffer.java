package com.marcin.pawlicki.trafficlazer.sniffer;

import com.marcin.pawlicki.trafficlazer.analyzer.MainAnalyzer;
import com.marcin.pawlicki.trafficlazer.listener.BasicPacketListener;
import com.marcin.pawlicki.trafficlazer.reporter.BasicReporter;
import com.marcin.pawlicki.trafficlazer.repository.BasicRepository;
import com.marcin.pawlicki.trafficlazer.simulator.AttackSimulator;
import com.marcin.pawlicki.trafficlazer.thread.CaptureThread;
import org.pcap4j.core.*;

import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class BasicSniffer {
    private final String addressToMonitor = "192.168.0.14"; // Personal address of network interface to monitor
    private final ExecutorService threadPool = Executors.newSingleThreadExecutor();
    private final MainAnalyzer securityAnalyzer = new MainAnalyzer();
    private final BasicReporter reporter = new BasicReporter();
    private final int maximumTransmissionUnit = 1403;
    private int snapshotLength = 65536; // Bytes - 0 means infinite buffer size
    private int readTimeout = 10;
    private PcapNetworkInterface networkInterface = null;
    private PcapHandle pcapCaptureHandle = null;
    private PcapHandle pcapSendHandle = null;

    public void startMonitoring() {
        findDeviceToCaptureFrom();
        openHandle();
        capturePackets();
    }

    public void findDeviceToCaptureFrom() {
        List<PcapNetworkInterface> allNetworkInterfaces = null;

        try {
            allNetworkInterfaces = Pcaps.findAllDevs();
        } catch (PcapNativeException e) {
            System.out.println("IOException occurred when searching for network devices.");
            e.printStackTrace();
        }

        if (allNetworkInterfaces != null) {
            for (PcapNetworkInterface networkInterface : allNetworkInterfaces) {
                String networkAddressesFound = networkInterface.getAddresses().toString();

                if (networkAddressesFound.contains(addressToMonitor)) {
                    this.networkInterface = networkInterface;
                    break;
                }
            }
        }
    }

    public void openHandle() {
        if (networkInterface == null) {
            System.out.println("No network device found.");
            System.exit(0);
        }

        try {
            pcapCaptureHandle = networkInterface.openLive(snapshotLength, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, readTimeout);
            pcapSendHandle = networkInterface.openLive(snapshotLength, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, readTimeout);
        } catch (PcapNativeException e) {
            System.out.println("PcapNativeExceptionOccurred when opening a handle.");
            e.printStackTrace();
        }
    }

    public void capturePackets() {
        PacketListener packetListener = new BasicPacketListener(pcapCaptureHandle);

        CaptureThread capturePacketsThread = new CaptureThread(pcapCaptureHandle, packetListener);
        threadPool.execute(capturePacketsThread);

        AttackSimulator attackSimulator = new AttackSimulator(pcapSendHandle, maximumTransmissionUnit, addressToMonitor);

        attackSimulator.simulateSynScan();
        attackSimulator.simulateARPSpoofing();

        try {
            Thread.sleep(10 * 1000);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            e.printStackTrace();
        }

        securityAnalyzer.findSecurityRisks(BasicRepository.getInstance().getSingleRunCapturedPackets());

        reporter.reportFoundIssues(securityAnalyzer);

        closeEverything();
    }

    private void closeEverything() {
        if (pcapCaptureHandle != null && pcapCaptureHandle.isOpen()) {
            pcapCaptureHandle.close();
        }

        if (pcapSendHandle != null && pcapSendHandle.isOpen()) {
            pcapSendHandle.close();
        }

        if (!threadPool.isShutdown()) {
            threadPool.shutdown();
        }
    }

    public int getSnapshotLength() {
        return snapshotLength;
    }

    public void setSnapshotLength(int snapshotLength) {
        this.snapshotLength = snapshotLength;
    }

    public int getReadTimeout() {
        return readTimeout;
    }

    public void setReadTimeout(int readTimeout) {
        this.readTimeout = readTimeout;
    }

    public String getAddressToMonitor() {
        return addressToMonitor;
    }

    public PcapHandle getPcapCaptureHandle() {
        return pcapCaptureHandle;
    }

    public void setPcapCaptureHandle(PcapHandle pcapCaptureHandle) {
        this.pcapCaptureHandle = pcapCaptureHandle;
    }

    public PcapNetworkInterface getNetworkInterface() {
        return networkInterface;
    }

    public void setNetworkInterface(PcapNetworkInterface networkInterface) {
        this.networkInterface = networkInterface;
    }

    public int getMaximumTransmissionUnit() {
        return maximumTransmissionUnit;
    }
}
