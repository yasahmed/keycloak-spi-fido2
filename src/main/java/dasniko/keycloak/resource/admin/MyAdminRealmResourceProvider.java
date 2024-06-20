package dasniko.keycloak.resource.admin;

import com.google.auto.service.AutoService;
import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.RealmModel;
import org.keycloak.services.resources.admin.AdminEventBuilder;
import org.keycloak.services.resources.admin.ext.AdminRealmResourceProvider;
import org.keycloak.services.resources.admin.ext.AdminRealmResourceProviderFactory;
import org.keycloak.services.resources.admin.permissions.AdminPermissionEvaluator;

@AutoService(AdminRealmResourceProviderFactory.class)
public class MyAdminRealmResourceProvider
	implements AdminRealmResourceProviderFactory, AdminRealmResourceProvider {

	public static final String PROVIDER_ID = "my-admin-rest-resource";

	@Override
	public AdminRealmResourceProvider create(KeycloakSession session) {
		return this;
	}

	@Override
	public Object getResource(KeycloakSession session, RealmModel realm, AdminPermissionEvaluator auth, AdminEventBuilder adminEvent) {
		return new MyAdminRealmResource(session, realm, auth);
	}

	@Override
	public void init(Config.Scope config) {
	}

	@Override
	public void postInit(KeycloakSessionFactory factory) {
	}

	@Override
	public void close() {
	}

	@Override
	public String getId() {
		return PROVIDER_ID;
	}

}
