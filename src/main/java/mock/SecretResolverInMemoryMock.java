package mock;

import org.didcommx.didcomm.common.VerificationMaterial;
import org.didcommx.didcomm.common.VerificationMaterialFormat;
import org.didcommx.didcomm.common.VerificationMethodType;
import org.didcommx.didcomm.secret.Secret;
import org.didcommx.didcomm.secret.SecretResolver;
import org.didcommx.didcomm.secret.SecretResolverInMemory;
import org.didcommx.didcomm.secret.SecretResolverEditable;

import java.util.*;

public class SecretResolverInMemoryMock implements SecretResolver {

    private List<Secret> secrets;

    public SecretResolverInMemory secretResolverInMemory;

    public Secret secret1 = new Secret(
            "did:example:alice#key-1",
            VerificationMethodType.JSON_WEB_KEY_2020,
            new VerificationMaterial(
                    VerificationMaterialFormat.JWK,
                    "{\"kty\":\"OKP\"," +
                            "\"d\":\"S160ItbVu2znR1NFs3xaay2Vy5vtjkaJHqPZLHcW-pQ\"," +
                            "\"crv\":\"Ed25519\"," +
                            "\"x\":\"1eESIYXnbLGwyNPeH0Nwxasd7exQJR2UD1OBGqoZDcg\"}"
            )
    );

    public Secret secret2 = new Secret(
            "did:example:alice#key-2",
            VerificationMethodType.JSON_WEB_KEY_2020,
            new VerificationMaterial(
                    VerificationMaterialFormat.JWK,
                    "{\"kty\":\"OKP\"," +
                            "\"d\":\"H1pzr9giveKVM2R_4StWO9edQGjkkQg_nE6SBqz5mZo\"," +
                            "\"crv\":\"X25519\"," +
                            "\"x\":\"F0g1QxzOMqTo00hg6PIf4zHY0_6FMe_OBujYsenYz3Q\"}"
            )
    );

    public void SetSecret() {
        secrets = new ArrayList<>();
        secrets.add(secret1);
        secrets.add(secret2);

        secretResolverInMemory = new SecretResolverInMemory(secrets);
    }

    @Override
    public Set<String> findKeys(List<String> list) {
        return secretResolverInMemory.findKeys(list);
    }

    @Override
    public Optional<Secret> findKey(String s) {
        return secretResolverInMemory.findKey(s);
    }
}