/*
 * This code is part of the ThornSec project.
 *
 * To learn more, please head to its GitHub repo: @privacyint
 *
 * Pull requests encouraged.
 */
package org.privacyinternational.thornsec.core.model.network;

import java.io.BufferedWriter;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.privacyinternational.thornsec.core.data.machine.*;
import org.privacyinternational.thornsec.core.data.network.NetworkData;
import org.privacyinternational.thornsec.core.exception.AThornSecException;
import org.privacyinternational.thornsec.core.exception.data.InvalidIPAddressException;
import org.privacyinternational.thornsec.core.exception.data.NoValidUsersException;
import org.privacyinternational.thornsec.core.exception.runtime.InvalidMachineModelException;
import org.privacyinternational.thornsec.core.exception.runtime.InvalidServerModelException;
import org.privacyinternational.thornsec.core.exception.runtime.InvalidTypeException;
import org.privacyinternational.thornsec.core.exec.ManageExec;
import org.privacyinternational.thornsec.core.exec.network.OpenKeePassPassphrase;
import org.privacyinternational.thornsec.core.iface.IUnit;
import org.privacyinternational.thornsec.core.model.machine.AMachineModel;
import org.privacyinternational.thornsec.core.model.machine.DedicatedModel;
import org.privacyinternational.thornsec.core.model.machine.ExternalOnlyDeviceModel;
import org.privacyinternational.thornsec.core.model.machine.HypervisorModel;
import org.privacyinternational.thornsec.core.model.machine.InternalOnlyDeviceModel;
import org.privacyinternational.thornsec.core.model.machine.ServerModel;
import org.privacyinternational.thornsec.core.model.machine.ServiceModel;
import org.privacyinternational.thornsec.core.model.machine.UserDeviceModel;
import org.privacyinternational.thornsec.core.model.machine.configuration.networking.NetworkInterfaceModel;
import inet.ipaddr.AddressStringException;
import inet.ipaddr.HostName;
import inet.ipaddr.IPAddress;
import inet.ipaddr.IPAddressString;
import inet.ipaddr.IncompatibleAddressException;

/**
 * Below the ThornsecModel comes the getNetworkModel().
 *
 * This model represents a given network; at its simplest, it just
 * holds information representing which machines are around.
 */
public class NetworkModel {
	private final String label;
	private Set<AMachineModel> machines;

	private Map<String, Collection<IUnit>> networkUnits;

	private Map<MachineType, IPAddress> defaultSubnets;

	NetworkModel(String label) {
		this.label = label;

		this.users = new LinkedHashMap<>();
		
		this.machines = null;
		this.networkUnits = null;
		
		populateNetworkDefaults();
	}

	private void populateNetworkDefaults() {
		buildDefaultSubnets();
	}

	private void buildDefaultSubnets() {
		this.defaultSubnets = new LinkedHashMap<>();

		try {
			this.defaultSubnets.put(MachineType.USER, new IPAddressString("172.16.0.0/16").toAddress());
			this.defaultSubnets.put(MachineType.SERVER, new IPAddressString("10.0.0.0/8").toAddress());
			this.defaultSubnets.put(MachineType.ADMIN, new IPAddressString("172.20.0.0/16").toAddress());
			this.defaultSubnets.put(MachineType.INTERNAL_ONLY, new IPAddressString("172.24.0.0/16").toAddress());
			this.defaultSubnets.put(MachineType.EXTERNAL_ONLY, new IPAddressString("172.28.0.0/16").toAddress());
			this.defaultSubnets.put(MachineType.GUEST, new IPAddressString("172.32.0.0/16").toAddress());
			this.defaultSubnets.put(MachineType.VPN, new IPAddressString("172.36.0.0/16").toAddress());
		} catch (AddressStringException | IncompatibleAddressException e) {
			// Well done, you shouldn't have been able to get here!
			e.printStackTrace();
		}

	}

	final public String getLabel() {
		return this.label;
	}

	final public Map<String, UserModel> getUsers() {
		return this.users;
	}

	/**
	 * Initialises the various models across our network, building and initialising
	 * all of our machines
	 *
	 * @throws AThornSecException
	 */
	void init() throws AThornSecException {

		buildMachines();
		buildUsers();

		// We want to initialise the whole network first before we start getting units
		for (AMachineModel machine : getMachines().values()) {
			machine.init();
		}

		// Now, step through our devices and run through their units.
		for (final AMachineModel device : getMachines(MachineType.DEVICE)) {
			putUnits(label, device.getUnits());
		}

		// We want to separate the Routers out; they need to be the very last
		// thing configured as it relies on the rest of the network being inited
		// & configured
		for (final AMachineModel server : getMachines(MachineType.SERVER)) {
			if (server.isType(MachineType.ROUTER)) {
				continue;
			}

			putUnits(server.getLabel(), server.getUnits());
		}

		// Finally, let's build our Routers
		for (final AMachineModel router : getMachines(MachineType.ROUTER)) {
			putUnits(router.getLabel(), router.getUnits());
		}
	}

	/**
	 * Builds the specialised Machine models from their data.
	 * @throws AThornSecException if something is broken
	 */
	private void buildMachines() throws AThornSecException {
		for (AMachineData machineData : getData().getMachines().values()) {

			AMachineModel machineModel = null;

			//Switches are probably easier to read, but they don't do logic
			if (machineData.isType(MachineType.INTERNAL_ONLY)) {
				machineModel = new InternalOnlyDeviceModel((InternalDeviceData) machineData, this);
			}
			else if (machineData.isType(MachineType.EXTERNAL_ONLY)) {
				machineModel = new ExternalOnlyDeviceModel((ExternalDeviceData) machineData, this);
			}
			else if (machineData.isType(MachineType.USER)) {
				machineModel = new UserDeviceModel((UserDeviceData) machineData, this);
			}
			else if (machineData.isType(MachineType.DEDICATED)) {
				machineModel = new DedicatedModel((DedicatedData) machineData, this);
			}
			else if (machineData.isType(MachineType.SERVICE)) {
				machineModel = new ServiceModel((ServiceData) machineData, this);
			}
			else if (machineData.isType(MachineType.HYPERVISOR)) {
				machineModel = new HypervisorModel((HypervisorData)machineData, this);
			}
			//We leave this down here, as Routers can potentially be Services
			else if (machineData.isType(MachineType.ROUTER)) {
				machineModel = new ServerModel((ServerData) machineData, this);
			}
			else {
				throw new InvalidTypeException("Unknown machine type for " + machineData.getLabel());
			}

			addMachine(machineModel);
		}
	}

	final public UserModel getConfigUserModel() throws NoValidUsersException {
		return this.users.get(getData().getUser());
	}

	private void buildUsers() throws AThornSecException {
		for (String username : getData().getUsers().keySet()) {
			this.users.put(username, new UserModel(getData().getUsers().get(username)));
		}
	}

	private void addMachine(AMachineModel machine) {
		if (this.machines == null) {
			this.machines = new LinkedHashMap<>();
		}
		this.machines.put(machine.getLabel(), machine);
	}

	private void putUnits(String label, Collection<IUnit> units) {
		if (this.networkUnits == null) {
			this.networkUnits = new LinkedHashMap<>();
		}

		this.networkUnits.put(label, units);
	}

	public Collection<NetworkInterfaceModel> getNetworkInterfaces(String machine) throws InvalidMachineModelException {
		Collection<NetworkInterfaceModel> interfaces = getMachineModel(machine).getNetworkInterfaces();

		if (interfaces == null) {
			interfaces = new ArrayList<>();
		}

		return interfaces;
	}

	/**
	 * @return the whole network. Be aware that you will have to cast the values
	 *         from this method; you are far better to use one of the specialised
	 *         methods
	 */
	public final Map<String, AMachineModel> getMachines() {
		return this.machines;
	}

	/**
	 * @param type
	 * @return A map of all machines of a given type, or an empty Set
	 */
	public Set<AMachineModel> getMachines(MachineType type) {
		Set<AMachineModel> machines = getMachines().values()
				.stream()
				.filter(machine -> machine.isType(type))
				.collect(Collectors.toSet());
	
		return machines;
	}

	/**
	 * @return A specific machine model.
	 */
	public final AMachineModel getMachineModel(String machine) throws InvalidMachineModelException {
		if (getMachines().containsKey(machine)) {
			return machines.get(machine);
		}

		throw new InvalidMachineModelException(machine + " is not a machine on your network");
	}

	public final void auditNonBlock(String server, OutputStream out, InputStream in, boolean quiet) throws InvalidMachineModelException {
		ManageExec exec = null;
		try {
			exec = getManageExec(server, "audit", out, quiet);
		} catch (InvalidServerModelException | IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		if (exec != null) {
			exec.manage();
		}
	}

	public final void auditAll(OutputStream out, InputStream in, boolean quiet) throws InvalidMachineModelException {
		for (final AMachineModel server : getMachines(MachineType.SERVER)) {
			ManageExec exec = null;
			try {
				exec = getManageExec(server.getLabel(), "audit", out, quiet);
			} catch (InvalidServerModelException | IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			if (exec != null) {
				exec.manage();
			}
		}
	}

	public final void configNonBlock(String server, OutputStream out, InputStream in) throws IOException, InvalidMachineModelException {
		final ManageExec exec = getManageExec(server, "config", out, false);
		if (exec != null) {
			exec.manage();
		}
	}

	public final void dryrunNonBlock(String server, OutputStream out, InputStream in) throws IOException, InvalidMachineModelException {
		final ManageExec exec = getManageExec(server, "dryrun", out, false);
		if (exec != null) {
			exec.manage();
		}
	}

	private final ManageExec getManageExec(String server, String action, OutputStream out, boolean quiet) throws IOException, InvalidMachineModelException {
		// need to do a series of local checks eg known_hosts or expected
		// fingerprint
		final OpenKeePassPassphrase pass = new OpenKeePassPassphrase((ServerModel)getMachineModel(server));

		final String audit = getScript(server, action, quiet);

		if (action.equals("dryrun")) {
			try {
				final SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd_HH.mm.ss");
				final String filename = server + "_" + dateFormat.format(new Date()) + ".sh";
				final Writer wr = new BufferedWriter(new OutputStreamWriter(new FileOutputStream(filename), StandardCharsets.UTF_8));
				wr.write(audit);
				wr.flush();
				wr.close();
			} catch (final FileNotFoundException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			return null;
		}

		if (pass.isADefaultPassphrase()) {
			System.out.println("FAIL: no password in keychain for " + server);
			System.out.println("Using the default password instead (this almost certainly won't work!)");
			return null;
		}

		// ManageExec exec = new ManageExec(this.getData().getUser(),
		// pass.getPassphrase(), serverModel.getIP(), this.getData().getSSHPort(server),
		// audit, out);
		final ManageExec exec = new ManageExec(((ServerModel)getMachineModel(server)), this, audit, out);
		return exec;
	}

	private String getScript(String server, String action, boolean quiet) {
		System.out.println("=======================" + getLabel() + ":" + server + "==========================");
		String line = getHeader(server, action) + "\n";
		final Collection<IUnit> units = this.networkUnits.get(server);
		for (final IUnit unit : units) {
			line += "#============ " + unit.getLabel() + " =============\n";
			line += getText(action, unit, quiet) + "\n";
		}
		line += getFooter(server, action);
		return line;
	}

	private String getText(String action, IUnit unit, boolean quiet) {
		String line = "";
		if (action.equals("audit")) {
			line = unit.genAudit(quiet);
		} else if (action.equals("config")) {
			line = unit.genConfig();
		} else if (action.equals("dryrun")) {
			line = unit.genConfig();
			// line = unit.genDryRun();
		}
		return line;
	}

	private String getHeader(String server, String action) {
		String line = "#!/bin/bash\n";
		line += "\n";
		line += "hostname=$(hostname)\n";
		line += "proceed_audit_passed=1\n";
		line += "\n";
		line += "echo \"Started " + action + " ${hostname} with config label: " + server + "\"\n";
		line += "passed=0; failed=0; fail_string=;";
		return line;
	}

	private String getFooter(String server, String action) {
		String line = "printf \"passed=${passed} failed=${failed}: ${fail_string}\"\n\n";
		line += "\n";
		line += "echo \"Finished " + action + " ${hostname} with config label: " + server + "\"";
		return line;
	}

	public void setData(NetworkData data) {
		this.data = data;
	}

	public NetworkData getData() {
		return this.data;
	}

	public String getKeePassDBPassphrase() {
		return null;
	}

	public String getKeePassDBPath(String server) throws URISyntaxException {
		return null;//getData().getKeePassDB(server);
	}

	public String getDomain() {
		return getData().getDomain().orElse("lan");
	}

	public Optional<UserModel> getUser(String username) {
		return Optional.ofNullable(this.users.get(username));
	}

	public IPAddress getSubnet(MachineType vlan) throws InvalidIPAddressException {
		try {
			return getData().getSubnet(vlan)
					.orElse(defaultSubnets.get(vlan));
		} catch (IncompatibleAddressException e) {
			throw new InvalidIPAddressException(e.getLocalizedMessage());
		}
	}

	/**
	 * Get the various subnets for our network.
	 * @return 
	 */
	public Map<MachineType, IPAddress> getSubnets() {
		if (getData().getSubnets().isEmpty()) {
			return this.defaultSubnets;
		}

		return Stream.of(getData().getSubnets().get(), this.defaultSubnets)
					.flatMap(map -> map.entrySet().stream())
					.collect(Collectors.toMap(
						Map.Entry::getKey,
						Map.Entry::getValue,
						(dataValue, defaultValue) -> dataValue)
					);
	}

	/**
	 * Get this network's upstream DNS servers
	 * @return as set in the data, or defaults
	 */
	public Collection<HostName> getUpstreamDNSServers() {
		return getData().getUpstreamDNSServers()
						.orElseGet(() ->
							Arrays.asList(new HostName("1.1.1.1:853"),
										new HostName("8.8.8.8:853")
							)
						);
	}

	/**
	 * Whether or not to do ad blocking
	 * @return as set in the data, or false
	 */
	public boolean doAdBlocking() {
		return getData().doAdBlocking().orElseGet(() -> false);
	}

	/**
	 * Whether or not to do build a Guest network that anyone can join
	 * @return as set in the data, or false
	 */
	public boolean buildAutoGuest() {
		return getData().buildAutoGuest().orElseGet(() -> false);
	}
}
