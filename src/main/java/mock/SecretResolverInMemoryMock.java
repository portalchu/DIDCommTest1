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
                            "\"d\":\"pFRUKkyzx4kHdJtFSnlPA9WzqkDT1HWV0xZ5OYZd2SY\"," +
                            "\"crv\":\"Ed25519\"," +
                            "\"x\":\"G-boxFB6vOZBu-wXkm-9Lh79I8nf9Z50cILaOgKKGww\"}"
            )
    );

    public Secret secret2 = new Secret(
            "did:example:alice#key-2",
            VerificationMethodType.JSON_WEB_KEY_2020,
            new VerificationMaterial(
                    VerificationMaterialFormat.JWK,
                    "{\"kty\":\"OKP\"," +
                            "\"d\":\"09b7321642fd79fb85c01bb72a5571ccbb7a358428968d3989ae812df0a08b01\"," +
                            "\"crv\":\"X25519\"," +
                            "\"x\":\"e00949828d30c93a5aff198e166284e000e817a86c2d2b3a952827a43ca9c367\"}"
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