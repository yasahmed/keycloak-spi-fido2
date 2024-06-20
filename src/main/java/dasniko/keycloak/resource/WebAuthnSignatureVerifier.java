package dasniko.keycloak.resource;

import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class WebAuthnSignatureVerifier {

    public static void main(String[] args) throws Exception {
        String base64ClientDataJSON = "eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiRVFIdGJKeGRFb3k0RXk5TWRIczVTY0x5YkZhNWJEUGN0QXAzQktnbERyNCIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3QwMCIsImNyb3NzT3JpZ2luIjpmYWxzZX0";
        String base64AuthenticatorData = "SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MdAAAAAA";
        String base64Signature = "MEYCIQCdSPRdPRG6uYq4HD0L-ccQoNgBh0C7JQL4nSXEvD8h4wIhANmcprMMZ3hrtFwUBVRHG2NIx8wl4nWUMG9d78cfpCSz";
        String base64PublicKey = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE7WkixrRR4b0C5bX_zJEpCozxmK6jhxOH46RJ-iqCTxKSR4Qm-ZNsegLAdiQijRX5zZi-XbvnYu63p1QuSpCa3g";

        // Decode the inputs
        byte[] clientDataJSON = Base64.getUrlDecoder().decode(base64ClientDataJSON);
        byte[] authenticatorData = Base64.getUrlDecoder().decode(base64AuthenticatorData);
        byte[] signature = Base64.getUrlDecoder().decode(base64Signature);
        byte[] publicKeyBytes = Base64.getUrlDecoder().decode(base64PublicKey);

        // Create the client data hash
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        byte[] clientDataHash = sha256.digest(clientDataJSON);

        // Concatenate authenticator data and client data hash
        byte[] signedData = new byte[authenticatorData.length + clientDataHash.length];
        System.arraycopy(authenticatorData, 0, signedData, 0, authenticatorData.length);
        System.arraycopy(clientDataHash, 0, signedData, authenticatorData.length, clientDataHash.length);

        // Convert the public key to the appropriate format
        KeyFactory keyFactory = KeyFactory.getInstance("EC");
        X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(publicKeyBytes);
        PublicKey publicKey = keyFactory.generatePublic(pubKeySpec);

        // Verify the signature
        Signature ecdsaVerify = Signature.getInstance("SHA256withECDSA");
        ecdsaVerify.initVerify(publicKey);
        ecdsaVerify.update(signedData);

        boolean isVerified = ecdsaVerify.verify(signature);

        System.out.println("Signature verified: " + isVerified);
    }
}

