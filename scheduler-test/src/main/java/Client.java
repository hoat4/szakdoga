import java.io.IOException;
import java.net.Socket;
import java.util.Map;

import static java.util.Map.entry;

public class Client {

    private static final Map<Integer, Integer> portsAndFlowLengths = Map.ofEntries(
            entry(50001, 100),
            entry(50002, 500),
            entry(50003, 1000),
            entry(50004, 5000),
            entry(50005, 10000),
            entry(50006, 50000),
            entry(50007, 100000),
            entry(50008, 500000),
            entry(50009, 1000000),
            entry(50010, 5000000),
            entry(50011, 10000000),
            entry(50012, 50000000),
            entry(50013, 100000000),
            entry(50014, 500000000),
            entry(50015, 1000000000)
    );

    private static final long launchTime = System.nanoTime();
    private static String destinationHost;

    public static void main(String[] args) throws IOException, InterruptedException {
        destinationHost = args[0];
        while (true) {
            beginFlow(50011);
            Thread.sleep(4000);
            beginFlow(50008);
            Thread.sleep(20000);
//            beginFlow(50011);
  //          Thread.sleep(1000);
        }
    }

    private static void beginFlow(int port) {
        int len = portsAndFlowLengths.get(port);
        System.out.println("Begin " + len + " at " + (System.nanoTime() - launchTime) / 1000000 + " ms");
        Thread.startVirtualThread(() -> {
            try (Socket s = new Socket(destinationHost, port)) {
                s.getOutputStream().write(new byte[len]);
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        });
    }
}