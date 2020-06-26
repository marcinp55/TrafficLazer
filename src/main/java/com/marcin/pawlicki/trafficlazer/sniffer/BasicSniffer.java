package com.marcin.pawlicki.trafficlazer.sniffer;

import com.marcin.pawlicki.trafficlazer.listener.BasicPacketListener;
import com.marcin.pawlicki.trafficlazer.threads.Task;
import org.pcap4j.core.*;
import org.pcap4j.packet.*;
import org.pcap4j.packet.namednumber.*;

import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class BasicSniffer {
    private final String addressToMonitor = "192.168.0.14"; // Personal address of network interface to monitor
    private final ExecutorService pool = Executors.newSingleThreadExecutor();
    private int snapshotLength = 65536; // Bytes - 0 means infinite buffer size
    private int readTimeout = 10;
    private PcapNetworkInterface networkInterface = null;
    private PcapHandle pcapHandle = null;
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
            pcapHandle = networkInterface.openLive(snapshotLength, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, readTimeout);
            pcapSendHandle = networkInterface.openLive(snapshotLength, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, readTimeout);
        } catch (PcapNativeException e) {
            System.out.println("PcapNativeExceptionOccurred when opening a handle.");
            e.printStackTrace();
        }
    }

    public void capturePackets() {
        PacketListener packetListener = new BasicPacketListener(pcapHandle);

        Task task = new Task(pcapHandle, packetListener);
        pool.execute(task);

        IpV4Packet.Builder ipV4PacketBuilder = new IpV4Packet.Builder();
        Packet ip4TestPacket = null;

        byte[] echoData = new byte[4000 - 28];
        for (int i = 0; i < echoData.length; i++) {
            echoData[i] = (byte) i;
        }

        IcmpV4EchoPacket.Builder echoBuilder = new IcmpV4EchoPacket.Builder();
        echoBuilder
                .identifier((short) 1)
                .payloadBuilder(new UnknownPacket.Builder().rawData(echoData));

        IcmpV4CommonPacket.Builder icmpV4CommonBuilder = new IcmpV4CommonPacket.Builder();
        icmpV4CommonBuilder
                .type(IcmpV4Type.ECHO)
                .code(IcmpV4Code.NO_CODE)
                .payloadBuilder(echoBuilder)
                .correctChecksumAtBuild(true);

        try {
            ip4TestPacket = ipV4PacketBuilder
                    .version(IpVersion.IPV4)
                    .tos(IpV4Rfc791Tos.newInstance((byte) 0))
                    .protocol(IpNumber.ICMPV4)
                    .srcAddr((Inet4Address) Inet4Address.getLocalHost())
                    .dstAddr((Inet4Address) Inet4Address.getByName("123.222.111.212"))
                    .build();
        } catch (UnknownHostException e) {
            e.printStackTrace();
        }

        try {
            for (int i = 0; i <= 1000; i++) {
                if (ip4TestPacket != null) {
                    System.out.println("SENDING PACKET");
                    pcapSendHandle.sendPacket(ip4TestPacket);
                }
            }
        } catch (PcapNativeException | NotOpenException e) {
            e.printStackTrace();
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

    public PcapHandle getPcapHandle() {
        return pcapHandle;
    }

    public void setPcapHandle(PcapHandle pcapHandle) {
        this.pcapHandle = pcapHandle;
    }

    public PcapNetworkInterface getNetworkInterface() {
        return networkInterface;
    }

    public void setNetworkInterface(PcapNetworkInterface networkInterface) {
        this.networkInterface = networkInterface;
    }
}
