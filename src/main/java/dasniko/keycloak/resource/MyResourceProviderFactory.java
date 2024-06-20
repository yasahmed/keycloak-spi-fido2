package dasniko.keycloak.resource;

import com.google.auto.service.AutoService;
import com.webauthn4j.WebAuthnManager;
import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.services.resource.RealmResourceProvider;
import org.keycloak.services.resource.RealmResourceProviderFactory;

/**
 * @author Niko Köbler, https://www.n-k.de, @dasniko
 */
@AutoService(RealmResourceProviderFactory.class)
public class MyResourceProviderFactory implements RealmResourceProviderFactory {

	public static final String PROVIDER_ID = "my-rest-resource";



	private WebAuthnManager webAuthnManager;

	@Override
	public RealmResourceProvider create(KeycloakSession keycloakSession) {
		return new MyResourceProvider(keycloakSession, webAuthnManager);
	}


	@Override
	public void init(Config.Scope scope) {
		// Initialize WebAuthnManager here
		this.webAuthnManager = WebAuthnManager.createNonStrictWebAuthnManager();
	}


	@Override
	public void postInit(KeycloakSessionFactory keycloakSessionFactory) {
	}

	@Override
	public void close() {
	}

	@Override
	public String getId() {
		return PROVIDER_ID;
	}
}
