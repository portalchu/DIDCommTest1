import org.apache.log4j.BasicConfigurator;

public class DIDCommTest {
    public static void main(String[] args) {
        BasicConfigurator.configure();

        Libsodium libsodium = new Libsodium();

        //libsodium.LibsodiumTestFun();
        libsodium.DIDCommTestFun();
    }


}
