package mock;

import org.didcommx.didcomm.common.VerificationMaterial;
import org.didcommx.didcomm.common.VerificationMaterialFormat;
import org.didcommx.didcomm.common.VerificationMethodType;
import org.didcommx.didcomm.secret.Secret;
import org.didcommx.didcomm.secret.SecretResolver;
import org.didcommx.didcomm.secret.SecretResolverInMemory;
import org.didcommx.didcomm.secret.SecretResolverEditable;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

public class SecretResolverInMemoryMock implements SecretResolverEditable {

    private List<Secret> secrets;
    public Secret secret1 = new Secret(
            "did:example:alice#key-1",
            VerificationMethodType.JSON_WEB_KEY_2020,
            new VerificationMaterial(
                    VerificationMaterialFormat.JWK,
                    "{\"kty\":\"OKP\"," +
                            "\"d\":\"f345a556a9b9cc7a48a28e21e2a91f728d91b69a3cbe8fadfd5383083c815923\"," +
                            "\"crv\":\"Ed25519\",}"
            )
    );


    @Override
    public Set<String> findKeys(List<String> list) {
        return null;
    }

    @Override
    public void addKey(Secret secret) {

    }

    @Override
    public List<String> getKids() {
        return null;
    }

    @Override
    public Optional<Secret> findKey(String s) {
        return Optional.empty();
    }
}