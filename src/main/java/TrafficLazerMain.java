import com.marcin.pawlicki.trafficlazer.sniffer.BasicSniffer;

public class TrafficLazerMain {
    public static void main(String[] args) {
        BasicSniffer basicSniffer = new BasicSniffer();

        basicSniffer.startMonitoring();
    }
}
