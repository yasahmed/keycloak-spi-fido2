package dasniko.keycloak.resource;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.cbor.CBORFactory;
import com.fasterxml.jackson.dataformat.cbor.CBORParser;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.util.Base64URL;
import com.upokecenter.cbor.CBORObject;
import com.webauthn4j.WebAuthnManager;
import com.webauthn4j.converter.exception.DataConversionException;
import com.webauthn4j.data.*;
import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier;
import com.webauthn4j.data.client.Origin;
import com.webauthn4j.data.client.challenge.Challenge;
import com.webauthn4j.data.client.challenge.DefaultChallenge;
import com.webauthn4j.server.ServerProperty;
import com.webauthn4j.util.Base64Util;
import org.junit.internal.runners.JUnit4ClassRunner;
import org.junit.jupiter.api.Test;
import org.junit.runner.RunWith;
import org.testcontainers.shaded.org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.testcontainers.shaded.org.bouncycastle.util.io.pem.PemObject;
import org.testcontainers.shaded.org.bouncycastle.util.io.pem.PemReader;

import java.io.StringReader;
import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Signature;
import java.security.interfaces.ECPublicKey;
import java.security.spec.*;
import java.util.*;


@RunWith(JUnit4ClassRunner.class)
public class MyResourceProviderTest {

	private static PublicKey decodePEMToPublicKey(String pem) throws Exception {
		String pemFormatted = "-----BEGIN PUBLIC KEY-----\n" + pem + "\n-----END PUBLIC KEY-----";
		PemReader pemReader = new PemReader(new StringReader(pemFormatted));
		PemObject pemObject = pemReader.readPemObject();
		byte[] pemContent = pemObject.getContent();

		X509EncodedKeySpec keySpec = new X509EncodedKeySpec(pemContent);
		KeyFactory keyFactory = KeyFactory.getInstance("EC");
		return keyFactory.generatePublic(keySpec);
	}

	private static CBORObject convertToCoseKey(PublicKey publicKey) throws Exception {
		SubjectPublicKeyInfo spki = SubjectPublicKeyInfo.getInstance(publicKey.getEncoded());
		byte[] encodedPoint = spki.getPublicKeyData().getBytes();

		// COSE key encoding (ES256)
		CBORObject coseKey = CBORObject.NewMap();
		coseKey.Add(CBORObject.FromObject(1), CBORObject.FromObject(2)); // kty: EC2
		coseKey.Add(CBORObject.FromObject(3), CBORObject.FromObject(-7)); // alg: ES256
		coseKey.Add(CBORObject.FromObject(-1), CBORObject.FromObject(1)); // crv: P-256
		coseKey.Add(CBORObject.FromObject(-2), CBORObject.FromObject(encodedPoint[1])); // x
		coseKey.Add(CBORObject.FromObject(-3), CBORObject.FromObject(encodedPoint[33])); // y

		return coseKey;
	}

	private static String base64UrlEncode(byte[] data) {
		return Base64.getUrlEncoder().withoutPadding().encodeToString(data);
	}

	public static String convertPemToCborBase64Url(String pemEncodedPublicKey) throws Exception {
		// Step 1: Decode the PEM formatted public key
		byte[] decodedPem = Base64URL.from(pemEncodedPublicKey).decode();

		// Step 2: Convert the decoded public key to JWK format
		X509EncodedKeySpec keySpec = new X509EncodedKeySpec(decodedPem);
		KeyFactory keyFactory = KeyFactory.getInstance("EC");
		PublicKey publicKey = keyFactory.generatePublic(keySpec);

		if (!(publicKey instanceof ECPublicKey)) {
			throw new IllegalArgumentException("The provided key is not an EC public key.");
		}
		ECPublicKey ecPublicKey = (ECPublicKey) publicKey;

		ECKey jwk = new ECKey.Builder(Curve.P_256, ecPublicKey).build();

		// Step 3: Serialize the JWK to CBOR
		ObjectMapper cborMapper = new ObjectMapper(new CBORFactory());
		byte[] cborBytes = cborMapper.writeValueAsBytes(jwk.toPublicJWK().toJSONObject());

		// Step 4: Convert the CBOR bytes to a Base64-url encoded string
		return Base64URL.encode(cborBytes).toString();
	}


	@Test
	public void testAnonymousEndpointGood() throws Exception {
		boolean isValid = FidoSignatureValidator.isValid(
				"pQECAyYgASFYIEvYXEWCoEMCjOaCwx8S-G-NWPwL7wFgmoMuqD5g1b6PIlgg1LmaM2weqIJ5gowly5eIsOPxBCgHqiFU8cvb3qvk45o"
				, "eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoidXFLTkVZQktUSXlRZEZqSG03SGJPZyIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3Q6OTA5MCIsImNyb3NzT3JpZ2luIjpmYWxzZX0",
				"SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MdAAAAAA",
				"MEUCICx9PQzg-g6kg1sG6ocewIbGZv0I9jVrmeTN0HkYhAFaAiEAp9spx2IS43YLGxdQVVw6T4gVCNrAfwjC6aQa77I-qNU");
		int h=1;
	}

	@Test
	public void testAnonymousEndpointCheck() throws Exception {
		boolean isValid = FidoSignatureValidator.isValid(
				"vyABAQIhWCAjPXAWmTY3zjgv0guGWj770sri7fh89Ncq5jkwRx0-diJYIQC206IOLWU4__gEue9vWyXpHY3viLes3AqVmVWQJgs9mQMm_w"
				, "eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoid0t2eTNVUUFvaTAzVkl0NEZkMng5LWpoa084bUpfdFFSczR6Tk5obTRIcyIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3Q6MzAwMCIsImNyb3NzT3JpZ2luIjpmYWxzZX0",
				"SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MdAAAAAA",
				"MEQCIDmeJ8flS33xKq3iEmBQYmkk6JSLZwtBbco3iJV1Yq9XAiAvIEYhBxp9PPHblpFOSfhldkYLICm6Z8LylSfom6RSRA");
		int h=1;
	}

	@Test
	public void testAnonymousEndpoint2() throws Exception {
		String pemEncodedPublicKey = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEPA6Lyt6SbvhtXo5R0ADvvAUCgFt-MaUsxIOp30R3B3uQmtw4OGkJkZV-IPqxxHEM2WwVAEY6161UID8hCJ2rRA";

		String cborBase64UrlEncodedPublicKey = convertPemToCborBase64Url(pemEncodedPublicKey);
		var ff = cborBase64UrlEncodedPublicKey;
		int h=1;
	}

	@Test
	public void testAnonymousEndpoint20() throws Exception {
		String base64UrlEncodedCbor = "v2NrdHliRUNjY3J2ZVAtMjU2YXh4K1BBNkx5dDZTYnZodFhvNVIwQUR2dkFVQ2dGdC1NYVVzeElPcDMwUjNCM3NheXgra0pyY09EaHBDWkdWZmlENnNjUnhETmxzRlFCR090ZXRWQ0FfSVFpZHEwUf8";

		// Step 1: Decode the Base64-url encoded string to get the CBOR data
		byte[] cborBytes = Base64URL.from(base64UrlEncodedCbor).decode();

		// Step 2: Deserialize the CBOR bytes to get the public key components
		ObjectMapper cborMapper = new ObjectMapper(new CBORFactory());
		Map<String, String> webAuthnKey = cborMapper.readValue(cborBytes, Map.class);

		String x = webAuthnKey.get("x");
		String y = webAuthnKey.get("y");

		// Step 3: Convert x and y to byte arrays
		byte[] xBytes = Base64URL.from(x).decode();
		byte[] yBytes = Base64URL.from(y).decode();

		// Step 4: Create ECPublicKeySpec
		ECPoint point = new ECPoint(new java.math.BigInteger(1, xBytes), new java.math.BigInteger(1, yBytes));


		// Use AlgorithmParameters to get ECParameterSpec
		AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");
		parameters.init(new ECGenParameterSpec("secp256r1"));
		ECParameterSpec ecParameterSpec = parameters.getParameterSpec(ECParameterSpec.class);

		KeyFactory keyFactory = KeyFactory.getInstance("EC");
		ECPublicKeySpec publicKeySpec = new ECPublicKeySpec(point, ecParameterSpec);
		ECPublicKey publicKey = (ECPublicKey) keyFactory.generatePublic(publicKeySpec);

		System.out.println("Public Key: " + publicKey);


		// Step 5: Generate the ECPublicKey
		KeyFactory keyFactory2 = KeyFactory.getInstance("EC");
		PublicKey ecPublicKey = keyFactory2.generatePublic(publicKeySpec);

		// Step 6: Convert the public key to X.509 format
		byte[] x509EncodedPublicKey = keyFactory.getKeySpec(ecPublicKey, X509EncodedKeySpec.class).getEncoded();

		// Step 7: Encode the X.509 encoded public key to Base64
		String base64EncodedPublicKey = Base64.getEncoder().encodeToString(x509EncodedPublicKey);

		System.out.println(base64EncodedPublicKey);
	}

	@Test
	public  void main2() {
		String base64EncodedPublicKey = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEPA6Lyt6SbvhtXo5R0ADvvAUCgFt+MaUsxIOp30R3B3uQmtw4OGkJkZV+IPqxxHEM2WwVAEY6161UID8hCJ2rRA==";

		byte[] decodedPublicKey = Base64.getDecoder().decode(base64EncodedPublicKey);
		byte[] cborEncodedPublicKey = CBORObject.FromObject(decodedPublicKey).EncodeToBytes();
		String base64UrlEncodedPublicKey = Base64.getUrlEncoder().withoutPadding().encodeToString(cborEncodedPublicKey);

		System.out.println("Base64URL-encoded CBOR-encoded WebAuthn public key credential: " + base64UrlEncodedPublicKey);

	}

	@Test
	public void testAnonymousEndpoint() throws Exception {

		String credentialPublicKey = "pQECAyYgASFYIC5kX1xUuGWqZjSRA-Ap3ElWHEEEekqgc2JSlutiAisnIlggakwsYu6fv-uLf59Aqv5gc9Sk0w4ZHu_7R26-PUaGdyg";

		// Decode the public key
		byte[] publicKeyBytes = Base64.getDecoder().decode(credentialPublicKey);

		CBORFactory cborFactory = new CBORFactory();
		CBORParser parser = cborFactory.createParser(publicKeyBytes);

		ObjectMapper objectMapper = new ObjectMapper(cborFactory);
		Map<String, Object> publicKeyMap = objectMapper.readValue(parser, Map.class);

		byte[] x = Base64.getDecoder().decode((String) publicKeyMap.get("x"));
		byte[] y = Base64.getDecoder().decode((String) publicKeyMap.get("y"));

		ECPoint point = new ECPoint(new BigInteger(1, x), new BigInteger(1, y));

		// Use AlgorithmParameters to get ECParameterSpec
		AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");
		parameters.init(new ECGenParameterSpec("secp256r1"));
		ECParameterSpec ecParameterSpec = parameters.getParameterSpec(ECParameterSpec.class);

		KeyFactory keyFactory = KeyFactory.getInstance("EC");
		ECPublicKeySpec publicKeySpec = new ECPublicKeySpec(point, ecParameterSpec);
		ECPublicKey publicKey = (ECPublicKey) keyFactory.generatePublic(publicKeySpec);

		System.out.println("Public Key: " + publicKey);

		// Step 2: Prepare the data to be signed
		String text = "Text to be signed";
		byte[] dataToSign = text.getBytes(java.nio.charset.StandardCharsets.UTF_8);

		// Step 3: Verify the signature
		// Replace this with your actual base64 encoded signature
		byte[] signature = Base64.getDecoder().decode("Base64EncodedSignature");

		Signature ecdsaVerify = Signature.getInstance("SHA256withECDSA");
		ecdsaVerify.initVerify(publicKey);
		ecdsaVerify.update(dataToSign);

		boolean result = ecdsaVerify.verify(signature);
		System.out.println("Signature valid: " + result);
	}


}
