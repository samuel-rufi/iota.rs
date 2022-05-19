package org.iota;

import org.iota.apis.NodeIndexerApi;

public class Main {

    public static void main(String[] args) {
        Client c = new Client(new ClientConfig("{ \"nodes\": [\"https://api.alphanet.iotaledger.net\" ]}"));

        System.out.println(c.getNodeInfo());
        System.out.println(c.getHealth("https://api.alphanet.iotaledger.net"));
        System.out.println(c.getTips());
        System.out.println(c.getMessage("0x6832742bb65e05b5b4a469a8e89f9dd551199f4316538f37b4b39d83043029a3"));
        System.out.println(c.getMessageRaw("0x6832742bb65e05b5b4a469a8e89f9dd551199f4316538f37b4b39d83043029a3"));
        System.out.println(c.getMessageMetadata("0x6832742bb65e05b5b4a469a8e89f9dd551199f4316538f37b4b39d83043029a3"));
        System.out.println(c.getMessageChildren("0x6832742bb65e05b5b4a469a8e89f9dd551199f4316538f37b4b39d83043029a3"));
        System.out.println(c.getOutput("0x00000000000000000000000000000000000000000000000000000000000000000000"));
        System.out.println(c.getReceiptsMigratedAt(5));
        System.out.println(c.getReceipts());
        System.out.println(c.getTreasury());
        System.out.println(c.getIncludedMessage("0x6832742bb65e05b5b4a469a8e89f9dd551199f4316538f37b4b39d83043029a3"));
        System.out.println(c.getMilestoneById("0x6832742bb65e05b5b4a469a8e89f9dd551199f4316538f37b4b39d83043029a3"));
        System.out.println(c.getMilestoneByIndex(3));
        System.out.println(c.getUtxoChangesByIndex(3));
        System.out.println(c.getUtxoChangesById("0x6832742bb65e05b5b4a469a8e89f9dd551199f4316538f37b4b39d83043029a3"));
        //System.out.println(c.getMilestoneByIdRaw("0x6832742bb65e05b5b4a469a8e89f9dd551199f4316538f37b4b39d83043029a3"));
        System.out.println(c.getPeers());

        System.out.println(c.getBasicOutputIds(new NodeIndexerApi.QueryParams()));
    }
}
