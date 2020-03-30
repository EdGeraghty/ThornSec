/*
 * This code is part of the ThornSec project.
 *
 * To learn more, please head to its GitHub repo: @privacyint
 *
 * Pull requests encouraged.
 */
package core.data.machine;

import java.io.IOException;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.Collection;
import java.util.LinkedHashSet;
import javax.json.JsonArray;
import javax.json.JsonObject;
import javax.json.JsonString;
import javax.json.JsonValue;
import javax.json.stream.JsonParsingException;

import core.StringUtils;
import core.data.machine.configuration.NetworkInterfaceData;
import core.exception.data.ADataException;
import core.exception.data.InvalidPortException;
import core.exception.data.InvalidPropertyException;
import inet.ipaddr.HostName;
import inet.ipaddr.IPAddress;

/**
 * This class represents a "Server" on our network - that is, a computer which
 * is providing a function on your network.
 *
 * I'd not be expecting you to instantiate this directly, (although you may, of
 * course!) rather one of its descendants.
 */
public class ServerData extends AMachineData {

	public enum SSHConnection {
		DIRECT, TUNNELLED
	}

	private Collection<HostName> sshSources;
	private Collection<String> profiles;
	private Collection<String> adminUsernames;
	private final Collection<IPAddress> remoteAdminIPAddresses;

	private Integer adminSSHConnectPort;
	private Integer sshListenPort;

	private Boolean update;

	private SSHConnection sshConnection;

	private URL debianMirror;
	private String debianDirectory;

	private String keePassDB;

	private Integer ram;
	private Integer cpus;

	public ServerData(String label) {
		super(label);

		this.sshSources = null;
		this.profiles = null;

		this.putType(MachineType.SERVER);

		this.adminUsernames = null;
		this.remoteAdminIPAddresses = null;

		this.adminSSHConnectPort = null;
		this.sshListenPort = null;

		this.update = null;

		this.sshConnection = null;

		this.debianDirectory = null;
		this.debianMirror = null;

		this.keePassDB = null;

		this.ram = null;
		this.cpus = null;
	}

	@Override
	public void read(JsonObject data) throws ADataException, JsonParsingException, IOException, URISyntaxException {
		super.read(data);

		// Build network interfaces
		if (data.containsKey("network_interfaces")) {
			final JsonObject networkInterfaces = data.getJsonObject("network_interfaces");

			if (networkInterfaces.containsKey("wan")) {
				final JsonArray wanIfaces = networkInterfaces.getJsonArray("wan");
				for (int i = 0; i < wanIfaces.size(); ++i) {
					final NetworkInterfaceData iface = new NetworkInterfaceData(getLabel());

					iface.read(wanIfaces.getJsonObject(i));
					putWANNetworkInterface(iface);
				}
			}

			if (networkInterfaces.containsKey("lan")) {
				final JsonArray lanIfaces = networkInterfaces.getJsonArray("lan");
				for (int i = 0; i < lanIfaces.size(); ++i) {
					final NetworkInterfaceData iface = new NetworkInterfaceData(getLabel());

					iface.read(lanIfaces.getJsonObject(i));
					putLANNetworkInterface(iface);
				}
			}
		}
		
		if (data.containsKey("admins")) {
			final JsonArray admins = data.getJsonArray("admins");
			for (final JsonValue admin : admins) {
				putAdmin(((JsonString) admin).getString());
			}
		}
		if (data.containsKey("ssh_sources")) {
			final JsonArray sources = data.getJsonArray("ssh_sources");
			for (final JsonValue source : sources) {
				putSSHSource(new HostName(((JsonString) source).getString()));
			}
		}
		if (data.containsKey("types")) {
			final JsonArray types = data.getJsonArray("types");
			for (final JsonValue type : types) {
				putType(((JsonString) type).getString());
			}
		}
		if (data.containsKey("profiles")) {
			final JsonArray profiles = data.getJsonArray("profiles");
			for (final JsonValue profile : profiles) {
				putProfile(((JsonString) profile).getString());
			}
		}
		if (data.containsKey("ssh_connect_port")) {
			setAdminPort(data.getInt("ssh_connect_port"));
		}
		if (data.containsKey("sshd_listen_port")) {
			setSSHListenPort(data.getInt("sshd_listen_port"));
		}
		if (data.containsKey("update")) {
			this.update = data.getBoolean("update");
		}
		if (data.containsKey("ssh_connection")) {
			this.sshConnection = SSHConnection.valueOf(data.getString("ssh_connection").toUpperCase());
		}
		if (data.containsKey("debian_mirror")) {
			setDebianMirror(new URL(data.getString("debian_mirror")));
		}
		if (data.containsKey("debian_directory")) {
			setDebianDirectory(data.getString("debian_directory"));
		}
		if (data.containsKey("keepassdb")) {
			setKeePassDB(data.getString("keepassdb"));
		}
		if (data.containsKey("cpus")) {
			setCPUs(data.getInt("cpus"));
		}
		if (data.containsKey("ram")) {
			setRAM(data.getString("ram"));
		}
	}

	private void setCPUs(Integer cpus) throws InvalidPropertyException {
		if (cpus < 1) {
			throw new InvalidPropertyException("You cannot have a machine with fewer than 1 CPUs!");
		}

		this.cpus = cpus;
	}

	private void setRAM(String ram) throws InvalidPropertyException {
		final Integer ramAsMB = StringUtils.stringToMegaBytes(ram);

		if (ramAsMB < 512) {
			throw new InvalidPropertyException("You cannot have a machine with less than 512mb of RAM");
		}

		this.ram = ramAsMB;
	}

	private void setKeePassDB(String keePassDB) {
		this.keePassDB = keePassDB;
	}

	private void setDebianDirectory(String dir) {
		this.debianDirectory = dir;
	}

	private void setDebianMirror(URL url) {
		this.debianMirror = url;
	}

	private void setSSHListenPort(Integer port) throws InvalidPortException {
		if ((port < 0) || (port > 65535)) {
			throw new InvalidPortException(port);
		}

		this.sshListenPort = port;
	}

	private void setAdminPort(Integer port) throws InvalidPortException {
		if ((port < 0) || (port > 65535)) {
			throw new InvalidPortException(port);
		}

		this.adminSSHConnectPort = port;
	}

	private void putProfile(String... profiles) {
		if (this.profiles == null) {
			this.profiles = new LinkedHashSet<>();
		}

		for (final String profile : profiles) {
			if (!this.profiles.contains(profile)) {
				this.profiles.add(profile);
			}
		}
	}

	private void putSSHSource(HostName... sources) {
		if (this.sshSources == null) {
			this.sshSources = new LinkedHashSet<>();
		}

		for (final HostName source : sources) {
			this.sshSources.add(source);
		}
	}

	private void putAdmin(String... admins) {
		if (this.adminUsernames == null) {
			this.adminUsernames = new LinkedHashSet<>();
		}

		for (final String admin : admins) {
			if (!this.adminUsernames.contains(admin)) {
				this.adminUsernames.add(admin);
			}
		}
	}

	public final Collection<String> getAdminUsernames() {
		return this.adminUsernames;
	}

	public final Collection<IPAddress> getRemoteAdminIPAddresses() {
		return this.remoteAdminIPAddresses;
	}

	public final Integer getAdminSSHConnectPort() {
		return this.adminSSHConnectPort;
	}

	public final Integer getSshListenPort() {
		return this.sshListenPort;
	}

	public final SSHConnection getSshConnection() {
		return this.sshConnection;
	}

	public final URL getDebianMirror() {
		return this.debianMirror;
	}

	public final String getDebianDirectory() {
		return this.debianDirectory;
	}

	public final Collection<String> getAdmins() {
		return this.adminUsernames;
	}

	public final SSHConnection getConnection() {
		return this.sshConnection;
	}

	public final Integer getAdminPort() {
		return this.adminSSHConnectPort;
	}

	public final Integer getSSHPort() {
		return this.sshListenPort;
	}

	public final Boolean getUpdate() {
		return this.update;
	}

	public final Collection<String> getProfiles() {
		return this.profiles;
	}

	public final Collection<IPAddress> getSSHSources() {
		return this.remoteAdminIPAddresses;
	}

	public final String getKeePassDB() {
		return this.keePassDB;
	}

	/**
	 * @return the ram in megabytes
	 */
	public final Integer getRAM() {
		return this.ram;
	}

	/**
	 * @return the number of CPUs assigned to this service
	 */
	public final Integer getCPUs() {
		return this.cpus;
	}
}
