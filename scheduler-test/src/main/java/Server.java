import java.io.IOException;
import java.io.InputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.List;
import java.util.Map;
import java.util.stream.IntStream;

public class Server {

    public static void main(String[] args) {
        for (int port : IntStream.rangeClosed(50001, 50015).boxed().toList()) {
            new Thread(() -> {
                try {
                    ServerSocket s = new ServerSocket(port);
                    while (true) {
                        Socket s2 = s.accept();
                        Thread.startVirtualThread(() -> {
                            try {
                                handleConnection(s2);
                            } catch (IOException e) {
                                throw new RuntimeException(e);
                            }
                        });
                    }
                } catch (IOException e) {
                    throw new RuntimeException(e);
                }
            }).start();
        }
    }

    private static void handleConnection(Socket socket) throws IOException {
        System.out.println("New connection: " + socket.getRemoteSocketAddress() + " -> " + socket.getLocalSocketAddress());
        InputStream in = socket.getInputStream();
        long begin = System.nanoTime();
        long readedBytes = 0;
        while (true) {
            long n = in.skip(10000);
            if (n == 0)
                break;
            else
                readedBytes += n;
            System.out.println("Readed 10000 bytes on " + socket.getRemoteSocketAddress() + " -> " + socket.getLocalSocketAddress());
        }
        long end = System.nanoTime();
        System.out.println("Connection finished, sum readed bytes is " + readedBytes + ": " + (end - begin) / 1_000_000 + " ms");
    }
}
