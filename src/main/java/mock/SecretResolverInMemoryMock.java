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

    public Secret secret3 = new Secret(
            "did:example:alice#key-3",
            VerificationMethodType.JSON_WEB_KEY_2020,
            new VerificationMaterial(
                    VerificationMaterialFormat.JWK,
                    "{\"kty\":\"EC\"," +
                            "\"d\":\"hzpirXFgetzlSNbMForoDupm-0uJOZDmdGAKEd_7rR4\"," +
                            "\"crv\":\"P-256\"," +
                            "\"x\":\"ivYUvybjaokTJantAbzGg96L4qkCjngDbliNp3yPkzM\"," +
                            "\"y\":\"ZtMsrzFOx-kdqQd_jJc2TnN_ASFJc2m0C7R2VhkfSJs\"}"
            )
    );

    public Secret secret4 = new Secret(
            "did:example:alice#key-4",
            VerificationMethodType.JSON_WEB_KEY_2020,
            new VerificationMaterial(
                    VerificationMaterialFormat.JWK,
                    "{\"kty\":\"EC\"," +
                            "\"d\":\"4Rcw7vIxAsLLpg2r_4P38RqfMMT1IssOPWy9HPVf6ZiHTUmvOAhWPijUwEHSic0T\"," +
                            "\"crv\":\"P-384\"," +
                            "\"x\":\"wKqfYznOMAtdHuMfzn3kxSXj-em2PHnzBRwalbJZRVfnrvO5zMgpwL0cvBw89QML\"," +
                            "\"y\":\"QLmGVThWGUF3yOo1WdBuuepKygs4xOnpZErxJrp33UjST8uaF75l7RR5YdDcuxPs\"}"
            )
    );

    public Secret secret5 = new Secret(
            "did:example:alice#key-5",
            VerificationMethodType.JSON_WEB_KEY_2020,
            new VerificationMaterial(
                    VerificationMaterialFormat.JWK,
                    "{\"kty\":\"EC\"," +
                            "\"d\":\"AfsrIZrgaCjx-f_UQ0RKc2yQ2rEkKBFkq5wemObC8U5a2H3qKQ1h7xtG1zV1dYkou1w68CpuazyH07x6-cAlPZll\"," +
                            "\"crv\":\"P-521\"," +
                            "\"x\":\"AdhTtFmjcApJOXNNH9DASL1V6_q3Vs_PUVX-5HxVMywPtX7dAO02_kUBej4Wf7hbwNXktnAkn-YXrOohGQ9IBMPS\"," +
                            "\"y\":\"AaG7be12d_uptxBUL1p9cey0TRTR5mxVMfe8OxZUjrRUgFmguBzEKUgPIIG9WQofvbjKxPcLVjHrPwGBH8QsHmcW\"}"
            )
    );

    public Secret secret6 = new Secret(
            "did:example:alice#key-6",
            VerificationMethodType.JSON_WEB_KEY_2020,
            new VerificationMaterial(
                    VerificationMaterialFormat.JWK,
                    "{\"kty\":\"EC\"," +
                            "\"d\":\"esirDdBuB0W89iyWvymmDBWSjKHF8XtZWS2ayxy5lUk\"," +
                            "\"crv\":\"secp256k1\"," +
                            "\"x\":\"YtMKHzQ7XfvEXGE_XvDNPYxhdvOGZes0UlNqkzXUNSM\"," +
                            "\"y\":\"M37EnuxZv85ucjHINqKadm9Y84t97hn8P5KRyxZIlmE\"}"
            )
    );

    public void SetSecret() {
        secrets = new ArrayList<>();
        secrets.add(secret1);
        secrets.add(secret2);
        secrets.add(secret3);
        secrets.add(secret4);
        secrets.add(secret5);
        secrets.add(secret6);

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