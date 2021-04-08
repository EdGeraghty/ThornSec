/*
 * This code is part of the ThornSec project.
 *
 * To learn more, please head to its GitHub repo: @privacyint
 *
 * Pull requests encouraged.
 */
package org.privacyinternational.thornsec.core.model.network;

import java.util.Collection;
import java.util.Optional;
import org.privacyinternational.thornsec.core.data.network.UserData;
import org.privacyinternational.thornsec.core.exception.AThornSecException;

/**
 * This model represents a User on our network. A User doesn't necessarily
 * have ADeviceModel 
 */
public class UserModel {

	private final UserData myData;

	public UserModel(UserData myData) {
		this.myData = myData;
	}

	public String getUsername() {
		return myData.getUsername().orElse(myData.getLabel());
	}

	public Optional<String> getSSHPublicKey() {
		return myData.getSSHKey();
	}

	public String getFullName() {
		return myData.getFullName().orElse("");
	}

	public Optional<String> getDefaultPassphrase() {
		return myData.getDefaultPassphrase();
	}

	public Optional<String> getWireGuardKey() {
		return myData.getWireGuardKey();
	}

	public Optional<String> getWireguardPSK() {
		return myData.getWireGuardPSK();
	}

	public Optional<Collection<String>> getWireGuardIPs() {
		return myData.getWireGuardIPs();
	}

	public String getHomeDirectory() {
		return myData.getHomeDirectory().orElse("/home/" + getUsername());
	}
}
