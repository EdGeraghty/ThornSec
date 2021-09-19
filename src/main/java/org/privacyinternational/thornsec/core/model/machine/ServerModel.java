/*
 * This code is part of the ThornSec project.
 *
 * To learn more, please head to its GitHub repo: @privacyint
 *
 * Pull requests encouraged.
 */
package org.privacyinternational.thornsec.core.model.machine;

import com.metapossum.utils.scanner.reflect.ClassesInPackageScanner;
import org.privacyinternational.thornsec.core.data.machine.ServerData;
import org.privacyinternational.thornsec.core.exception.AThornSecException;
import org.privacyinternational.thornsec.core.exception.data.machine.InvalidUserException;
import org.privacyinternational.thornsec.core.exception.runtime.InvalidGuestOSException;
import org.privacyinternational.thornsec.core.iface.IUnit;
import org.privacyinternational.thornsec.core.model.network.NetworkModel;
import org.privacyinternational.thornsec.core.model.network.UserModel;
import org.privacyinternational.thornsec.core.profile.AProfile;
import org.privacyinternational.thornsec.core.unit.SimpleUnit;
import org.privacyinternational.thornsec.core.unit.fs.FileAppendUnit;
import org.privacyinternational.thornsec.profile.firewall.AFirewallProfile;
import org.privacyinternational.thornsec.profile.guest.AOS;
import org.privacyinternational.thornsec.profile.guest.Debian;
import org.privacyinternational.thornsec.profile.machine.configuration.Processes;
import org.privacyinternational.thornsec.profile.machine.configuration.UserAccounts;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Optional;

/**
 * This Class represents a Server. It is either used directly, or is called via
 * one of its children.
 */
public class ServerModel extends AMachineModel {
	// Server-specific
	private final Processes runningProcesses;
	// private final ConfigFiles configFiles;
	private final UserAccounts users;

	private AOS os;
	private String iso;
	private String isoSHA512;

	public ServerModel(ServerData myData, NetworkModel networkModel) throws AThornSecException {
		super(myData, networkModel);

		this.runningProcesses = new Processes(this);
		this.users = new UserAccounts(this);

		this.setOS();
		this.addProfiles();
		this.addAdmins();
		this.addISODetails();
	}

	@Override
	public ServerData getData() {
		return (ServerData) super.getData();
	}

	private void addISODetails() {
		this.iso = getData().getIsoUrl();
		this.isoSHA512 = getData().getIsoSha512();
	}

	private void addAdmins() throws InvalidUserException {
		if (getData().getAdmins().isPresent()) {
			addAdmins(getData().getAdmins().get());
		}
	}

	private void addAdmins(Collection<String> usernames) throws InvalidUserException {
		for (String username : usernames) {
			if (getNetworkModel().getUserModel(username).isPresent()) {
				//TODO
				//this.users.addAdmin(getNetworkModel().getUser(username).get());
			}
			else {
				throw new InvalidUserException(username);
			}
		}
	}

	@Override
	public Collection<IUnit> getUnits() throws AThornSecException {
		final Collection<IUnit> units = new ArrayList<>();

		units.add(new SimpleUnit("host", "proceed", "echo \"ERROR: Configuring with hostname mismatch\";", "sudo -S hostname;", getLabel(), "pass"));

		units.add(new FileAppendUnit("auto_logout", "proceed", "TMOUT=" + ((2 * 60) * 60) + "\n" + // two hour timeout
				"readonly TMOUT\n" + "export TMOUT", "/etc/profile",
				"Couldn't set the serial timeout. This means users who forget to log out won't be auto logged out after two hours."));

		units.addAll(getOS().getUnits());

		units.addAll(super.getUnits());

		units.addAll(serverConfig());

		units.addAll(this.users.getUnits());

		units.addAll(this.runningProcesses.getUnits());

		return units;
	}

	private Collection<IUnit> serverConfig() {
		final Collection<IUnit> units = new ArrayList<>();

		// Shouldn't /really/ be doing this out here, but these should be the only RAW
		// sockets, in the only circumstances, in a TS network...
		String excludeKnownRaw = "";
		// if (this.isRouter()) {
		excludeKnownRaw += " | grep -v \"dhcpd\"";
		// if (Objects.equals(this.getExtConn(), "ppp")) {
		// excludeKnownRaw += " | grep -v \"pppd\"";
		// }
		// }

		units.add(new SimpleUnit("no_raw_sockets", "lsof_installed", "", "sudo lsof | grep RAW" + excludeKnownRaw, "", "pass",
				"There are raw sockets running on this machine.  This is almost certainly a sign of compromise."));

		// Verify our PAM modules haven't been tampered with
		// https://www.trustedsec.com/2018/04/malware-linux/
		units.add(new SimpleUnit("pam_not_tampered", "proceed", "", "find /lib/$(uname -m)-linux-gnu/security/ | xargs dpkg -S | cut -d ':' -f 1 | uniq | xargs sudo dpkg -V", "",
				"pass", "There are unexpected/tampered PAM modules on this machine.  This is almost certainly an indicator that this machine has been compromised!"));

		return units;
	}


	public final void addProcessString(String psString) {
		getProcessModel().addProcess(psString);
	}

	protected Processes getProcessModel() {
		return this.runningProcesses;
	}

	public UserAccounts getUserModel() {
		return this.users;
	}

	public final void addSystemUsername(String username) {
		this.users.addUsername(username);
	}

	public Boolean getAutoUpdate() {
		return getData().getUpdate().orElse(true);
	}

	public Integer getSSHListenPort() {
		return getData().getAdminPort().orElse(65422);
	}

	public Integer getCPUs() {
		return getData().getCPUs().orElse(2);
	}

	protected void setOS() throws AThornSecException {
		if (getData().getOS().isEmpty()) {
			return;
		}

		this.os = reflectedOS(getData().getOS().get());
	}

	protected AOS reflectedOS(String os) throws InvalidGuestOSException {
		Collection<Class<?>> classes;
		try {
			classes = new ClassesInPackageScanner()
					.setResourceNameFilter((packageName, fileName) ->
							fileName.equals(os + ".class"))
					.scan("org.privacyinternational.thornsec.profile.guest");

			return (AOS) Class.forName(classes.iterator().next().getName())
					.getDeclaredConstructor(ServerModel.class)
					.newInstance(this);
		} catch (Exception e) {
			throw new InvalidGuestOSException("Guest OS " + os + " threw an"
					+ " exception\n\n" + e.getLocalizedMessage());
		}
	}

	public AOS getOS() throws AThornSecException {
		if (null == this.os) {
			return new Debian(this);
		}

		return this.os;
	}

	public Optional<String> getIsoUrl() {
		return Optional.ofNullable(this.iso);
	}

	public void setIsoURL(String url) {
		this.iso = url;
	}

	public void setIsoSHA512(String checksum) {
		this.isoSHA512 = checksum;
	}

	public Optional<String> getIsoSHA512() {
		return Optional.ofNullable(this.isoSHA512);
	}

	public Collection<? extends IUnit> getISODownloadUnits() {
		// TODO Auto-generated method stub
		return new ArrayList<>();
	}

	public String getPackageMirror() throws InvalidGuestOSException {
		return this.os.getPackageMirror();
	}

	public String getPackageDirectory() {
		return this.os.getPackageDirectory();
	}

	public Collection<UserModel> getAdmins() {
		//TODO
		return new ArrayList<>();
		//return this.users;
	}
}
