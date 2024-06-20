package dasniko.keycloak.resource;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.cbor.CBORFactory;
import com.upokecenter.cbor.CBORObject;
import com.webauthn4j.WebAuthnManager;
import com.webauthn4j.converter.exception.DataConversionException;
import com.webauthn4j.data.*;
import com.webauthn4j.data.attestation.AttestationObject;
import com.webauthn4j.data.attestation.authenticator.AttestedCredentialData;
import com.webauthn4j.data.attestation.authenticator.AuthenticatorData;
import com.webauthn4j.data.attestation.authenticator.COSEKey;
import com.webauthn4j.data.attestation.authenticator.EC2COSEKey;
import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier;
import com.webauthn4j.data.client.Origin;
import com.webauthn4j.data.client.challenge.Challenge;
import com.webauthn4j.data.client.challenge.DefaultChallenge;
import com.webauthn4j.server.ServerProperty;
import com.webauthn4j.util.Base64UrlUtil;
import com.webauthn4j.util.Base64Util;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.keycloak.credential.CredentialModel;
import org.keycloak.credential.CredentialProvider;
import org.keycloak.credential.WebAuthnCredentialProvider;
import org.keycloak.credential.WebAuthnCredentialProviderFactory;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.credential.WebAuthnCredentialModel;
import org.keycloak.services.managers.AppAuthManager;
import org.keycloak.services.managers.AuthenticationManager.AuthResult;
import org.keycloak.services.resource.RealmResourceProvider;

import java.io.IOException;
import java.math.BigInteger;
import java.security.*;
import java.security.interfaces.ECPublicKey;
import java.security.spec.*;
import java.util.*;
import java.util.stream.Collectors;

/**
 * @author Niko Köbler, https://www.n-k.de, @dasniko
 */
@RequiredArgsConstructor
@Slf4j
//@Path("/realms/{realm}/" + MyResourceProviderFactory.PROVIDER_ID)
public class MyResourceProvider implements RealmResourceProvider {


	private final KeycloakSession session;
	private final WebAuthnManager webAuthnManager;


	@Override
	public Object getResource() {
		return this;
	}

	@Override
	public void close() {
	}

	@GET
	@Path("hello")
	@Produces(MediaType.APPLICATION_JSON)
	public Response helloAnonymous() {
		log.info("{}",webAuthnManager.getRegistrationDataValidator().getOriginValidator());
		log.info("{}",webAuthnManager.getAuthenticationDataValidator().getOriginValidator());
		log.info("{}",webAuthnManager.getAuthenticationDataValidator().isCrossOriginAllowed());
		return Response.ok(Map.of("hello", 1)).build();
	}

	@GET
	@Path("hell2")
	@Produces(MediaType.APPLICATION_JSON)
	public Response helloAuthenticated2() {
		return Response.ok(Map.of("hello", "1")).build();
	}

	@GET
	@Path("hell3")
	public Response helloAuthenticated3() {
		return Response.ok(Map.of("hello", "1")).build();
	}

	@GET
	@Path("hello-auth")
	@Produces(MediaType.APPLICATION_JSON)
	public Response helloAuthenticated() {
		AuthResult auth = checkAuthUser();
		return Response.ok(Map.of("hello", auth.getUser().getUsername())).build();
	}


	public static String generateRandomString(int length) {
		String CHARACTERS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
		int CHARACTERS_LENGTH = CHARACTERS.length();
		Random random = new Random();
		StringBuilder stringBuilder = new StringBuilder(length);

		for (int i = 0; i < length; i++) {
			int randomIndex = random.nextInt(CHARACTERS_LENGTH);
			stringBuilder.append(CHARACTERS.charAt(randomIndex));
		}

		return stringBuilder.toString();
	}

    /*@OPTIONS
	@Path("{any:.*}")
	public Response preflight() {
		HttpRequest request = session.getContext().getContextObject(HttpRequest.class);
		return Cors.add(request, Response.ok()).auth().preflight().build();
	}*/

	@GET
	@Path("challenge")
	@Produces(MediaType.APPLICATION_JSON)
	public Response challenge(@QueryParam("userId") String userId) throws Exception {
		RealmModel realmx = session.getContext().getRealm();
		boolean isValid = false;


		UserModel user = session.users().getUserByUsername(realmx, userId);
		var cred =  user.credentialManager().getStoredCredentialsStream().filter(x->x.getType().equals("webauthn-passwordless"))
				.findFirst()
				.orElseThrow(()->new RuntimeException("ERROR NOT FIDO pass found"));

		CredentialData credentialData = new ObjectMapper().readValue(cred.getCredentialData(), CredentialData.class);


		String credentialId = credentialData.getCredentialId();

		SecureRandom random = new SecureRandom();
		byte[] challenge = new byte[32];
		random.nextBytes(challenge);
		String encodedChallenge = Base64.getUrlEncoder().withoutPadding().encodeToString(challenge);

		return Response
				.status(200)
				.entity(ChallengeReturn.builder()
						.challenge(encodedChallenge)
						.credentialId(credentialId).build())

				.build();
	}

	@GET
	@Path("fido2")
	@Produces(MediaType.APPLICATION_JSON)
	public Response fido2(@QueryParam("clientDataJSON") String clientDataJSON,@QueryParam("authenticatorData") String authenticatorData,@QueryParam("signature") String signature,@QueryParam("userId") String userId) throws Exception {
		RealmModel realmx = session.getContext().getRealm();
		boolean isValid = false;


		UserModel user = session.users().getUserByUsername(realmx, userId);


		user.credentialManager().getStoredCredentialsStream().forEach(x->{
			log.info(">>>>>> getType : {}",x.getType());
			log.info(">>>>>> getCredentialData : {}",x.getCredentialData());
			log.info(">>>>>> getSecretData : {}",x.getSecretData());
		});

		var cred =  user.credentialManager().getStoredCredentialsStream().filter(x->x.getType().equals("webauthn-passwordless"))
				.findFirst()
				.orElseThrow(()->new RuntimeException("ERROR NOT FIDO pass found"));

		CredentialData credentialData = new ObjectMapper().readValue(cred.getCredentialData(), CredentialData.class);


		String publicKey = credentialData.getCredentialPublicKey();
		log.info(">>>>>> Public Key : {}",publicKey);

		try {
			log.info("FUCK publicKey : {}",publicKey);
			log.info("FUCK clientDataJSON : {}",clientDataJSON);
			log.info("FUCK authenticatorData : {}",authenticatorData);
			log.info("FUCK signature : {}",signature);

			isValid = FidoSignatureValidator.isValid(publicKey, clientDataJSON, authenticatorData,signature);
			log.info("is valid : {}",isValid);
		}catch (Exception e) {
			log.error("{}",e.getStackTrace());
		}

		return Response
				.status(200)
				.header("Access-Control-Allow-Origin", "*")
				.header("Access-Control-Allow-Headers", "origin, content-type, accept, authorization")
				.header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS, HEAD")
				.entity(VerificationResponse.builder().success(isValid).message("ok").build())

				.build();
	}


	@GET
	@Path("fido")
	@Produces(MediaType.APPLICATION_JSON)
	public Response fido(@QueryParam("clientDataJSON") String clientDataJSON,@QueryParam("authenticatorData") String authenticatorData,@QueryParam("signature") String signature) throws Exception {

		AuthResult auth = checkAuthUser();
		boolean isValid = false;


		auth.getUser().credentialManager().getStoredCredentialsStream().forEach(x->{
			log.info(">>>>>> getType : {}",x.getType());
			log.info(">>>>>> getCredentialData : {}",x.getCredentialData());
			log.info(">>>>>> getSecretData : {}",x.getSecretData());
		});

		var cred =  auth.getUser().credentialManager().getStoredCredentialsStream().filter(x->x.getType().equals("webauthn-passwordless"))
				.findFirst()
				.orElseThrow(()->new RuntimeException("ERROR NOT FIDO pass found"));

		CredentialData credentialData = new ObjectMapper().readValue(cred.getCredentialData(), CredentialData.class);


		String publicKey = credentialData.getCredentialPublicKey();
		log.info(">>>>>> Public Key : {}",publicKey);

    try {
		isValid = FidoSignatureValidator.isValid(publicKey, clientDataJSON, authenticatorData,signature);
	}catch (Exception e) {
		log.error("{}",e.getStackTrace());
	}

		return Response
				.status(200)
				.header("Access-Control-Allow-Origin", "*")
				.header("Access-Control-Allow-Headers", "origin, content-type, accept, authorization")
				.header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS, HEAD")
				.entity(VerificationResponse.builder().success(isValid).message("ok").build())

				.build();

	}


	private AuthResult checkAuthUser() {

		AuthResult auth = new AppAuthManager.BearerTokenAuthenticator(session).authenticate();

		if (auth == null) {
			throw new NotAuthorizedException("Bearer");
		}
		return auth;
	}

	@POST
	@Path("/challengex")
	@Produces(MediaType.APPLICATION_JSON)
	public Response generateChallenge() {
		SecureRandom random = new SecureRandom();
		byte[] challenge = new byte[32];
		random.nextBytes(challenge);
		String encodedChallenge = Base64.getUrlEncoder().withoutPadding().encodeToString(challenge);
		return Response.ok("{\"challenge\":\"" + encodedChallenge + "\"}").build();
	}

	public String encodeToBase64Url(byte[] data) {
		return Base64.getUrlEncoder().withoutPadding().encodeToString(data);
	}
	public byte[] publicKeyToCbor(PublicKey publicKey) throws IOException {
		ECPublicKey ecPublicKey = (ECPublicKey) publicKey; // Cast to specific type if you are sure of it
		byte[] x = ecPublicKey.getW().getAffineX().toByteArray();
		byte[] y = ecPublicKey.getW().getAffineY().toByteArray();

		// Create a map to represent the EC public key in COSE format
		Map<Integer, Object> publicKeyCose = new HashMap<>();
		publicKeyCose.put(1, 2); // Key Type: EC2
		publicKeyCose.put(3, -7); // Algorithm: ES256
		publicKeyCose.put(-1, 1); // Curve: P-256
		publicKeyCose.put(-2, x); // x-coordinate
		publicKeyCose.put(-3, y); // y-coordinate

		// Use CBORFactory to generate CBOR encoding
		CBORFactory cborFactory = new CBORFactory();
		ObjectMapper cborMapper = new ObjectMapper(cborFactory);
		return cborMapper.writeValueAsBytes(publicKeyCose);
	}
	@POST
	@Path("/register")
	@Consumes(MediaType.APPLICATION_JSON)
	@Produces(MediaType.APPLICATION_JSON)
	public Response completeRegistration(Fido2RegistrationRequest request) throws NoSuchAlgorithmException, InvalidKeySpecException, IOException, InvalidParameterSpecException {


		String clientDataJSON = request.getClientDataJSON();
		String attestationObject = request.getAttestationObject();

		log.info("challenge : {}",request.getChallenge());
		log.info("userId : {}",request.getUserId());
		log.info("clientDataJSON : {}",clientDataJSON);
		log.info("attestationObject : {}",attestationObject);

		// Verify the challenge and registration data
		String clientExtensionJSON = "{}";
		Set<String> transports = new HashSet<>(Arrays.asList("hybrid", "internal", "ble"));

// Server properties
		Origin origin = new Origin("http://localhost:3000");
		String rpId = "localhost";
		Challenge challenge = new DefaultChallenge(Base64.getUrlDecoder().decode(request.getChallenge()));
		byte[] tokenBindingId = null; // Assuming tokenBindingId is not used
		ServerProperty serverProperty = new ServerProperty(origin, rpId, challenge, tokenBindingId);

		// Expectations
		List<PublicKeyCredentialParameters> pubKeyCredParams = Arrays.asList(
				new PublicKeyCredentialParameters(PublicKeyCredentialType.PUBLIC_KEY, COSEAlgorithmIdentifier.ES256)
		);
		boolean userVerificationRequired = false;
		boolean userPresenceRequired = true;

		RegistrationRequest registrationRequest = new RegistrationRequest(Base64Util.decode(attestationObject), Base64Util.decode(clientDataJSON), clientExtensionJSON, transports);
		RegistrationParameters registrationParameters = new RegistrationParameters(serverProperty, pubKeyCredParams, userVerificationRequired, userPresenceRequired);
		RegistrationData registrationData;


		try {
			registrationData = webAuthnManager.parse(registrationRequest);
		} catch (DataConversionException e) {
			// If you would like to handle WebAuthn data structure parse error, please catch DataConversionException
			throw e;
		}

		var data = webAuthnManager.validate(registrationData, registrationParameters);

		AttestationObject attestationObject3 = data.getAttestationObject();

		// Extract the authenticator data from the attestation object
		AuthenticatorData authenticatorData = attestationObject3.getAuthenticatorData();

		// Extract the attested credential data from the authenticator data
		AttestedCredentialData attestedCredentialData = authenticatorData.getAttestedCredentialData();

		// Extract the public key from the attested credential data
		byte[] publicKeyBytes = attestedCredentialData.getCOSEKey().getPublicKey().getEncoded();

		COSEKey coseKey = attestedCredentialData.getCOSEKey();

		log.info("TOTO1 {}",registrationData.getAttestationObject().getAuthenticatorData().getAttestedCredentialData().getCOSEKey().getAlgorithm());
		log.info("TOTO2 {}",coseKey.getAlgorithm());

		log.info("MOMO1 {}",registrationData.getAttestationObject().getAuthenticatorData().getAttestedCredentialData().getCOSEKey().getKeyType());
		log.info("MOMO2 {}",coseKey.getKeyType());

		log.info("LOLO1 {}",((EC2COSEKey) registrationData.getAttestationObject().getAuthenticatorData().getAttestedCredentialData().getCOSEKey()).getX());
		log.info("LOLO2 {}",((EC2COSEKey) coseKey).getX());


			EC2COSEKey ecPublicKey = (EC2COSEKey) coseKey;
			// EC public key specifics: curve, x, y
			byte[] xx = ecPublicKey.getX();
			byte[] yy = ecPublicKey.getY();



				ECPoint ecPoint = new ECPoint(new BigInteger(1, xx), new BigInteger(1, yy));

				AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");
				parameters.init(new ECGenParameterSpec("secp256r1"));
				ECParameterSpec ecParameterSpec = parameters.getParameterSpec(ECParameterSpec.class);

				KeyFactory keyFactory = KeyFactory.getInstance("EC");
				ECPublicKeySpec publicKeySpec = new ECPublicKeySpec(ecPoint, ecParameterSpec);
				PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);
				byte[] cborData = publicKeyToCbor(publicKey);
				String base64UrlCborXX = encodeToBase64Url(cborData);
				System.out.println("Base64-url Encoded CBOR: " + base64UrlCborXX);



				// Use the generated public key (e.g., store it, use it in cryptographic operations)


			// Here you would handle the raw x and y values, possibly converting them to another format or storing them as needed






		// Encode the CBOR bytes to Base64-url
		String base64UrlCbor = Base64.getUrlEncoder().withoutPadding().encodeToString(publicKeyBytes);


		RealmModel realm = session.getContext().getRealm();
		UserModel userModel = session.users().addUser(realm, request.getUserId());
		userModel.setEmail(request.getUserId()+"@ahmed1.com");
		userModel.setFirstName(request.getUserId());
		userModel.setLastName(request.getUserId());
		userModel.setEnabled(true);
		userModel.setEmailVerified(true);

		// Extract and save required information
		String aaguid = registrationData.getAttestationObject().getAuthenticatorData().getAttestedCredentialData().getAaguid().getValue().toString();
		String attestationStatementFormat = registrationData.getAttestationObject().getAttestationStatement().toString();
		long counter = registrationData.getAttestationObject().getAuthenticatorData().getSignCount();
		String credentialId = Base64UrlUtil.encodeToString(registrationData.getAttestationObject().getAuthenticatorData().getAttestedCredentialData().getCredentialId());
		//String credentialPublicKey = Base64UrlUtil.encodeToString(registrationData.getAttestationObject().getAuthenticatorData().getAttestedCredentialData().getCOSEKey().getPublicKey().getEncoded());
		String credentialPublicKey = base64UrlCbor;
		String transportss = registrationData.getTransports().stream().map(x->x.getValue()).collect(Collectors.joining(","));
		log.info("aaguid : {}",aaguid);
		log.info("attestationStatementFormat : {}",attestationStatementFormat);
		log.info("counter : {}",counter);
		log.info("credentialId : {}",credentialId);
		log.info("credentialPublicKey : {}",credentialPublicKey);
		log.info("transportss : {}",transportss);


		;


//    public static WebAuthnCredentialModel create(String credentialType, String userLabel, String aaguid, String credentialId, String attestationStatement, String credentialPublicKey, long counter, String attestationStatementFormat, Set<String> transports) {
		// Set WebAuthn credentials
		//CredentialProvider credentialProvider = session.getProvider(WebAuthnCredentialProvider.class);
		WebAuthnCredentialProvider credentialProvider = (WebAuthnCredentialProvider) session.getProvider(CredentialProvider.class, WebAuthnCredentialProviderFactory.PROVIDER_ID);


		WebAuthnCredentialModel webAuthnCredential = WebAuthnCredentialModel.create(
				"webauthn-passwordless",
				request.getUserId(),
				aaguid,
				credentialId,
				clientDataJSON,
				(base64UrlCborXX),
				0,
				registrationData.getAttestationObject().getFormat(),
				registrationData.getTransports().stream().toList().stream().map(x->x.getValue()).collect(Collectors.toSet())

		);
		CredentialModel c= credentialProvider.createCredential( realm, userModel, webAuthnCredential);

		return Response.status(Response.Status.OK).entity("{\"status\":\"true\"}").build();
	}

	public  String convertPemToCbos(String base64UrlKey) {

		// Decode the key from Base64-URL
		byte[] keyBytes = Base64.getUrlDecoder().decode(base64UrlKey);

		// Extract the x and y coordinates from the key bytes
		byte[] xBytes = new byte[32];
		byte[] yBytes = new byte[32];
		System.arraycopy(keyBytes, 1, xBytes, 0, 32);  // skip the first byte which is 0x04
		System.arraycopy(keyBytes, 33, yBytes, 0, 32);

		// Construct the CBOR structure for the public key
		CBORObject coseKey = CBORObject.NewMap();
		coseKey.Add(CBORObject.FromObject(1), CBORObject.FromObject(2)); // Key Type: EC2
		coseKey.Add(CBORObject.FromObject(3), CBORObject.FromObject(-7)); // Algorithm: ES256
		coseKey.Add(CBORObject.FromObject(-1), CBORObject.FromObject(1)); // Curve: P-256
		coseKey.Add(CBORObject.FromObject(-2), CBORObject.FromObject(xBytes)); // x-coordinate
		coseKey.Add(CBORObject.FromObject(-3), CBORObject.FromObject(yBytes)); // y-coordinate

		// Encode the CBOR structure to bytes
		byte[] cborBytes = coseKey.EncodeToBytes();

		// Encode the CBOR bytes to Base64-url
		return Base64.getUrlEncoder().withoutPadding().encodeToString(cborBytes);

	}
}
