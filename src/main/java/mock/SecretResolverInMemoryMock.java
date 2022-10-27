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
                            "\"d\":\"geF/ugy7o77ko7V8IzaqS0XNRkvCcA+hm3wbpNr2BoI=\"," +
                            "\"crv\":\"Ed25519\"," +
                            "\"x\":\"hcVNRzH7mQArc+o1Tf9zHOh85xj+EdIFglZQYYEaoEA=\"}"
            )
    );

    public Secret secret2 = new Secret(
            "did:example:alice#key-2",
            VerificationMethodType.JSON_WEB_KEY_2020,
            new VerificationMaterial(
                    VerificationMaterialFormat.JWK,
                    "{\"kty\":\"OKP\"," +
                            "\"d\":\"r04d4PkdaggRG3DEaK7jzIjf5bNP0tTyorvYFYbH5UU=\"," +
                            "\"crv\":\"X25519\"," +
                            "\"x\":\"qCNxmHo8okIehEck/YX+/KLU07ySk0OGxe91FT4wLBE=\"}"
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