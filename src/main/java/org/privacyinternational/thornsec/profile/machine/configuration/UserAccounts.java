/*
 * This code is part of the ThornSec project.
 *
 * To learn more, please head to its GitHub repo: @privacyint
 *
 * Pull requests encouraged.
 */
package org.privacyinternational.thornsec.profile.machine.configuration;

import java.util.ArrayList;
import java.util.Collection;

import org.privacyinternational.thornsec.core.exception.data.machine.InvalidServerException;
import org.privacyinternational.thornsec.core.iface.IUnit;
import org.privacyinternational.thornsec.core.model.machine.ServerModel;
import org.privacyinternational.thornsec.core.profile.AProfile;
import org.privacyinternational.thornsec.core.unit.SimpleUnit;

public class UserAccounts extends AProfile {

	private final Collection<String> usernames;

	public UserAccounts(ServerModel server) throws InvalidServerException {
		super(server);

		this.usernames = new ArrayList<>();

		//TODO
		//for (final String admin : getNetworkModel().getData().getAdmins(getLabel())) {
		//	this.usernames.add(admin);
		//}

		this.usernames.add("root");
		this.usernames.add("daemon");
		this.usernames.add("bin");
		this.usernames.add("sys");
		this.usernames.add("sync");
		this.usernames.add("games");
		this.usernames.add("man");
		this.usernames.add("lp");
		this.usernames.add("mail");
		this.usernames.add("news");
		this.usernames.add("uucp");
		this.usernames.add("proxy");
		this.usernames.add("www-data");
		this.usernames.add("backup");
		this.usernames.add("list");
		this.usernames.add("irc");
		this.usernames.add("gnats");
		this.usernames.add("nobody");
		this.usernames.add("systemd-timesync");
		this.usernames.add("systemd-network");
		this.usernames.add("systemd-resolve");
		this.usernames.add("systemd-bus-proxy");
		this.usernames.add("systemd-coredump");
		this.usernames.add("_apt");
		this.usernames.add("messagebus");
		this.usernames.add("sshd");
		this.usernames.add("statd");
	}

	@Override
	public Collection<IUnit> getUnits() {
		String grepString = "awk -F':' '{ print $1 }' /etc/passwd";
		final Collection<IUnit> units = new ArrayList<>();

		for (final String username : this.usernames) {
			grepString += " | grep -Ev \"^" + username + "\\$\"";
		}

		// We want to be able to see what users are there if the audit fails!
		grepString += " | tee /dev/stderr | grep -v 'tee /dev/stderr'";

		units.add(new SimpleUnit("no_unexpected_users", "proceed", "", grepString, "", "pass",
				"There are unexpected user accounts on this machine.  This could be a sign that the machine is compromised, or it could be "
						+ "entirely innocent.  Please check the usernames carefully to see if there's any cause for concern."));

		return units;
	}

	public void addUsername(String username) {
		this.usernames.add(username);
	}
}
