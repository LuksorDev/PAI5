package com.company;

import java.io.IOException;
import java.sql.Timestamp;


import org.pcap4j.core.*;
import org.pcap4j.core.PcapNetworkInterface.PromiscuousMode;
import org.pcap4j.packet.*;
import org.pcap4j.util.NifSelector;


public class Sniffer {

    PcapNetworkInterface getNetworkDevice() {
        PcapNetworkInterface device = null;
        try {
            device = new NifSelector().selectNetworkInterface();
        } catch (IOException e) {
            System.out.println("Error with selecting device");
        }
        return device;
    }

    PcapHandle createHandle(PcapNetworkInterface device) {
        int snapshotLength = 65536;
        int readTimeout = 100;
        PcapHandle handle;

        try {
            handle = device.openLive(snapshotLength, PromiscuousMode.PROMISCUOUS, readTimeout);
            handle.setFilter("tcp", BpfProgram.BpfCompileMode.OPTIMIZE);
            return handle;

        } catch (PcapNativeException | NotOpenException e) {
            System.out.println("Error with creating handle");
            return null;
        }
    }

    static void packetListener(PcapHandle handle) {
        PacketListener listener = new PacketListener() {
            @Override
            public void gotPacket(Packet packet) {
                        String srcHost = packet.get(IpV4Packet.class).getHeader().getSrcAddr().getHostAddress();
                        String dstHost = packet.get(IpV4Packet.class).getHeader().getDstAddr().getHostAddress();
                        Timestamp date = handle.getTimestamp();
                        System.out.println("Date: " + date + "   Source: " + srcHost + "   Destination: " + dstHost);
                }
        };

        try {
            int maxPackets = 30;
            handle.loop(maxPackets, listener);
        } catch (InterruptedException | NotOpenException | PcapNativeException e) {
            System.out.println("Error with reading packets");
        }
    }


    public static void main(String[] args){

         Sniffer sniffer = new Sniffer();

        PcapNetworkInterface device = sniffer.getNetworkDevice();

        PcapHandle handle = sniffer.createHandle(device);
        packetListener(handle);

        handle.close();


    }
}