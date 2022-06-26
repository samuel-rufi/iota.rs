package node_api_core;

import org.iota.Client;
import org.iota.types.ClientConfig;
import org.iota.types.ClientException;
import org.iota.types.MilestonePayload;
import org.iota.types.ids.MilestoneId;

public class GetMilestoneByIndex {

    private static final String DEFAULT_TESTNET_NODE_URL = "http://localhost:14265";
    private static ClientConfig config = new ClientConfig("{ \"nodes\": [\"" + DEFAULT_TESTNET_NODE_URL + "\" ], \"nodeSyncEnabled\": false}");

    public static void main(String[] args) throws ClientException {
        // Build the client.
        Client client = new Client(config);

        // Set up a milestone index.
        int milestoneIndex = client.getNodeInfo().getNodeInfo().get("status").getAsJsonObject().get("confirmedMilestone").getAsJsonObject().get("index").getAsInt();

        // Get the milestone.
        MilestonePayload milestone = client.getMilestoneByIndex(milestoneIndex);

        // Print the milestone.
        System.out.println(milestone);
    }

}
