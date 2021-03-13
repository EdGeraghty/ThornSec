/*
 * This code is part of the ThornSec project.
 *
 * To learn more, please head to its GitHub repo: @privacyint
 *
 * Pull requests encouraged.
 */
package org.privacyinternational.thornsec.core.data.machine;

import java.util.Arrays;
import java.util.Collection;
import java.util.EnumSet;
import java.util.LinkedHashSet;
import java.util.NoSuchElementException;
import java.util.Optional;
import java.util.Set;
import javax.json.JsonArray;
import javax.json.JsonObject;
import javax.json.JsonString;
import javax.json.JsonValue;

import org.privacyinternational.thornsec.core.StringUtils;
import org.privacyinternational.thornsec.core.data.machine.configuration.NetworkInterfaceData;
import org.privacyinternational.thornsec.core.data.machine.configuration.NetworkInterfaceData.Direction;
import org.privacyinternational.thornsec.core.exception.data.ADataException;
import org.privacyinternational.thornsec.core.exception.data.InvalidPortException;
import org.privacyinternational.thornsec.core.exception.data.InvalidPropertyException;
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

	public enum GuestOS {
		DEBIAN_64("debian_amd64"),
		DEBIAN_32("alpine_x86"),
		ALPINE_64("alpine_amd64"),
		ALPINE_32("alpine_x86");
	
		public static final Set<GuestOS> alpine = EnumSet.of(ALPINE_32, ALPINE_64);
		public static final Set<GuestOS> debian = EnumSet.of(DEBIAN_32, DEBIAN_64);
	
		private final String guestOS;
	
		GuestOS(String guestOS) {
			this.guestOS = guestOS;
		}
	
		@Override
		public String toString() {
			return this.guestOS;
		}
	}

	private Set<HostName> sshSources;
	private Set<String> profiles;
	private Set<String> adminUsernames;
	private final Set<IPAddress> remoteAdminIPAddresses;

	private Integer adminSSHConnectPort;
	private Integer sshListenPort;

	private Boolean update;

	private SSHConnection sshConnection;

	private String packageMirror;
	private String packageMirrorDirectory;

	private String keePassDB;

	private Integer ram;
	private Integer cpus;
	protected GuestOS guestOS;
	protected String iso;
	protected String isoSHA512;

	public ServerData(String label) {
		super(label);

		this.sshSources = null;
		this.profiles = null;

		this.adminUsernames = null;
		this.remoteAdminIPAddresses = null;

		this.adminSSHConnectPort = null;
		this.sshListenPort = null;

		this.update = null;

		this.sshConnection = null;

		this.packageMirrorDirectory = null;
		this.packageMirror = null;

		this.keePassDB = null;

		this.ram = null;
		this.cpus = null;
	}

	@Override
	public ServerData read(JsonObject data) throws ADataException {
		super.read(data);

		readNICs(data);
		readAdmins(data);
		readSSHSources(data);
		readProfiles(data);
		readSSHSettings(data);
		readUpdate(data);
		readMirror(data);
		readKeepassDbPath(data);
		readCPUs(data);
		readRAM(data);

		return this;
	}
	
	private NetworkInterfaceData readNIC(Direction dir, JsonObject nic) throws ADataException {
		NetworkInterfaceData newIface = new NetworkInterfaceData(getLabel());
		newIface.read(nic);
		newIface.setDirection(dir);

		Optional<NetworkInterfaceData> existingIface = getNetworkInterface(newIface.getIface());
		if (existingIface.isPresent()) {
			newIface = existingIface.get();
			newIface.read(nic);
		}

		return newIface;
	}
	
	private Optional<NetworkInterfaceData> getNetworkInterface(String iface) {
		try {
			return Optional.ofNullable(
					getNetworkInterfaces()
					.orElseThrow()
					.get(iface)
			);
		}
		catch (NoSuchElementException e) {
			return Optional.ofNullable(null);
		}
	}

	private void readNICs(JsonObject data, String key, Direction direction) throws ADataException { 
		if (!data.containsKey(key)) {
			return;
		}

		final JsonArray ifaces = data.getJsonArray(key);
		for (int i = 0; i < ifaces.size(); ++i) {
			NetworkInterfaceData nicData = readNIC(direction, ifaces.getJsonObject(i));

			if (getNetworkInterface(nicData.getIface()).isEmpty()) {
				putNetworkInterface(nicData);
			}
			else {
				nicData.getAddresses().ifPresent(addresses -> {
					getNetworkInterface(nicData.getIface())
						.get()
						.addAddress(addresses.toArray(IPAddress[]::new));
				});
			}
		}
	}
	
	private void readNICs(JsonObject data) throws ADataException {
		if (!data.containsKey("network_interfaces")) {
			return;
		}
		
		data = data.getJsonObject("network_interfaces");

		readNICs(data, "wan", Direction.WAN);
		readNICs(data, "lan", Direction.LAN);
	}
	
	/**
	 * @param data
	 * @throws InvalidPropertyException
	 */
	private void readRAM(JsonObject data) throws InvalidPropertyException {
		if (!data.containsKey("ram")) {
			return;
		}
		
		setRAM(data.getString("ram"));
	}

	/**
	 * @param data
	 * @throws InvalidPropertyException
	 */
	private void readCPUs(JsonObject data) throws InvalidPropertyException {
		if (!data.containsKey("cpus")) {
			return;
		}
		
		setCPUs(data.getInt("cpus"));
	}

	/**
	 * @param data
	 */
	private void readKeepassDbPath(JsonObject data) {
		if (!data.containsKey("keepassdb")) {
			return;
		}
		
		setKeePassDB(data.getString("keepassdb"));
	}

	/**
	 * @param data
	 * @throws InvalidPropertyException
	 */
	private void readMirror(JsonObject data) throws InvalidPropertyException {
		readMirrorURL(data);
		readMirrorDirectory(data);
	}

	/**
	 * @param data
	 */
	private void readMirrorDirectory(JsonObject data) {
		if (!data.containsKey("mirror_directory")) {
			return;
		}
		
		setMirrorDirectory(data.getString("mirror_directory"));
	}

	/**
	 * @param data
	 * @throws InvalidPropertyException
	 */
	private void readMirrorURL(JsonObject data) throws InvalidPropertyException {
		if (!data.containsKey("mirror")) {
			return;
		}

		setMirror(data.getString("mirror"));
	}

	/**
	 * @param data
	 */
	private void readUpdate(JsonObject data) {
		if (!data.containsKey("update")) {
			return;
		}
		
		this.update = data.getBoolean("update");
	}

	/**
	 * @param data
	 * @throws InvalidPortException
	 */
	private void readSSHSettings(JsonObject data) throws InvalidPortException {
		readSSHConnectPort(data);
		readSSHdListenPort(data);
		readSSHConnection(data);
	}

	/**
	 * @param data
	 */
	private void readSSHConnection(JsonObject data) {
		if (!data.containsKey("ssh_connection")) {
			return;
		}
		
		String connection = data.getString("ssh_connection");
		this.sshConnection = SSHConnection.valueOf(connection.toUpperCase());
	}

	/**
	 * @param data
	 * @throws InvalidPortException
	 */
	private void readSSHdListenPort(JsonObject data) throws InvalidPortException {
		if (!data.containsKey("sshd_listen_port")) {
			return;
		}
		
		setSSHListenPort(data.getInt("sshd_listen_port"));
	}

	/**
	 * @param data
	 * @throws InvalidPortException
	 */
	private void readSSHConnectPort(JsonObject data) throws InvalidPortException {
		if (data.containsKey("ssh_connect_port")) {
			setAdminPort(data.getInt("ssh_connect_port"));
		}
	}

	/**
	 * @param data
	 */
	private void readProfiles(JsonObject data) {
		if (!data.containsKey("profiles")) {
			return;
		}

		data.getJsonArray("profiles").forEach(profile ->
			putProfile(((JsonString)profile).getString())
		);
	}

	/**
	 * @param data
	 */
	private void readSSHSources(JsonObject data) {
		if (!data.containsKey("ssh_sources")) {
			return;
		}
		
		data.getJsonArray("ssh_sources")
			.forEach(source ->
				putSSHSource(new HostName(((JsonString) source).getString()))
			);
	}

	/**
	 * @param data
	 * @throws InvalidPropertyException
	 */
	private void readAdmins(JsonObject data) throws InvalidPropertyException {
		if (!data.containsKey("admins")) {
			return;
		}

		for (final JsonValue admin : data.getJsonArray("admins")) {
			putAdmin(((JsonString) admin).getString());
		}
	}

	private void setCPUs(Integer cpus) throws InvalidPropertyException {
		if (cpus < 1) {
			throw new InvalidPropertyException("You cannot have a machine with"
					+ " fewer than 1 CPUs!");
		}

		this.cpus = cpus;
	}

	private void setRAM(String ram) throws InvalidPropertyException {
		final Integer ramAsMB = StringUtils.stringToMegaBytes(ram);

		if (ramAsMB < 512) {
			throw new InvalidPropertyException("You cannot have a machine with"
					+ "less than 512mb of RAM");
		}

		this.ram = ramAsMB;
	}

	private void setKeePassDB(String keePassDB) {
		this.keePassDB = keePassDB;
	}

	private void setMirrorDirectory(String dir) {
		this.packageMirrorDirectory = dir;
	}

	private void setMirror(String url) {
		this.packageMirror = url;
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

		this.profiles.addAll(Arrays.asList(profiles));
	}

	private void putSSHSource(HostName... sources) {
		if (this.sshSources == null) {
			this.sshSources = new LinkedHashSet<>();
		}

		this.sshSources.addAll(Arrays.asList(sources));
	}

	private void putAdmin(String... admins) throws InvalidPropertyException {
		if (this.adminUsernames == null) {
			this.adminUsernames = new LinkedHashSet<>();
		}

		for (final String admin : admins) {
			if (!this.adminUsernames.contains(admin)) {
				this.adminUsernames.add(admin);
			}
			else {
				throw new InvalidPropertyException(admin + " is duplicated");
			}
		}
	}

	public final Optional<Collection<String>> getAdminUsernames() {
		return Optional.ofNullable(this.adminUsernames);
	}

	public final Optional<Collection<IPAddress>> getRemoteAdminIPAddresses() {
		return Optional.ofNullable(this.remoteAdminIPAddresses);
	}

	public final Optional<Integer> getAdminSSHConnectPort() {
		return Optional.ofNullable(this.adminSSHConnectPort);
	}

	public final Optional<Integer> getSshListenPort() {
		return Optional.ofNullable(this.sshListenPort);
	}

	public final Optional<SSHConnection> getSshConnection() {
		return Optional.ofNullable(this.sshConnection);
	}

	public final Optional<String> getPackageMirror() {
		return Optional.ofNullable(this.packageMirror);
	}

	public final Optional<String> getPackageMirrorDirectory() {
		return Optional.ofNullable(this.packageMirrorDirectory);
	}

	public final Optional<Collection<String>> getAdmins() {
		return Optional.ofNullable(this.adminUsernames);
	}

	public final Optional<SSHConnection> getConnection() {
		return Optional.ofNullable(this.sshConnection);
	}

	public final Optional<Integer> getAdminPort() {
		return Optional.ofNullable(this.adminSSHConnectPort);
	}

	public final Optional<Integer> getSSHPort() {
		return Optional.ofNullable(this.sshListenPort);
	}

	public final Optional<Boolean> getUpdate() {
		return Optional.ofNullable(this.update);
	}

	public final Optional<Set<String>> getProfiles() {
		return Optional.ofNullable(this.profiles);
	}

	public final Optional<Collection<IPAddress>> getSSHSources() {
		return Optional.ofNullable(this.remoteAdminIPAddresses);
	}

	public final Optional<String> getKeePassDB() {
		return Optional.ofNullable(this.keePassDB);
	}

	/**
	 * @return the ram in megabytes
	 */
	public final Optional<Integer> getRAM() {
		return Optional.ofNullable(this.ram);
	}

	/**
	 * @return the number of CPUs assigned to this service
	 */
	public final Optional<Integer> getCPUs() {
		return Optional.ofNullable(this.cpus);
	}

	protected void readOS() {
		if (!getData().containsKey("os")) {
			return;
		}

		setOS(getData().getString("os"));		
	}

	private void setOS(String os) {
		this.guestOS = GuestOS.valueOf(os);
	}

	public Optional<GuestOS> getOS() {
		return Optional.ofNullable(this.guestOS);
	}

	protected void readISO() {
		this.iso = getData().getString("iso_url", null);
		this.isoSHA512 = getData().getString("iso_sha512", null);
	}

	/**
	 * @return the URL to use for building this service
	 */
	public final String getIsoUrl() {
		return this.iso;
	}

	/**
	 * @return the expected SHA512SUM of the Debian ISO
	 */
	public final String getIsoSha512() {
		return this.isoSHA512;
	}
}
