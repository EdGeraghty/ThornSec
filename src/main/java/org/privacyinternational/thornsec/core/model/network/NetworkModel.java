/*
 * This code is part of the ThornSec project.
 *
 * To learn more, please head to its GitHub repo: @privacyint
 *
 * Pull requests encouraged.
 */
package org.privacyinternational.thornsec.core.model.network;

import org.privacyinternational.thornsec.core.data.machine.AMachineData;
import org.privacyinternational.thornsec.core.data.network.NetworkData;
import org.privacyinternational.thornsec.core.exception.AThornSecException;
import org.privacyinternational.thornsec.core.exception.data.NoValidUsersException;
import org.privacyinternational.thornsec.core.exception.runtime.InvalidMachineModelException;
import org.privacyinternational.thornsec.core.exception.runtime.InvalidServerModelException;
import org.privacyinternational.thornsec.core.exec.ManageExec;
import org.privacyinternational.thornsec.core.iface.IUnit;
import org.privacyinternational.thornsec.core.model.AModel;
import org.privacyinternational.thornsec.core.model.machine.*;
import org.privacyinternational.thornsec.type.AMachineType;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Function;
import java.util.function.Predicate;
import java.util.stream.Collectors;

/**
 * Below the ThornsecModel comes the getNetworkModel().
 *
 * This model represents a given network; at its simplest, it just
 * holds information representing which machines are around.
 */
public class NetworkModel extends AModel {
	private final Set<UserModel> users = new HashSet<>();
	private final Set<AMachineModel> machines = new HashSet<>();

	private final Map<String, Collection<IUnit>> networkUnits = new LinkedHashMap<>();

	NetworkModel(NetworkData data) throws AThornSecException {
		super(data);

		buildUsers();
		buildMachines();

		// Now get the units, working our way up the stack...
		for (final AMachineModel device : getMachines(DeviceModel.class)) {
			putUnits(device);
		}

		for (final AMachineModel server : getMachines(ServerModel.class)) {
			putUnits(server);
		}

		for (final AMachineModel service : getMachines(ServiceModel.class)) {
			putUnits(service);
		}
	}

	@Override
	public NetworkData getData() {
		return (NetworkData) super.getData();
	}

	final public Set<UserModel> getUsers() {
		return this.users;
	}

	@Override
	public Collection<IUnit> getUnits() throws AThornSecException {
		return new ArrayList<>();
	}

	/**
	 * Builds the specialised Machine models from their data.
	 *
	 * @throws AThornSecException if something is broken
	 */
	private void buildMachines() throws AThornSecException {
		for (AMachineData machineData : getData().getMachines()) {
			machines.add(ModelFactory.modelFromData(machineData, this));
		}
	}

	final public UserModel getConfigUserModel() throws NoValidUsersException {
		return getUserModel(getData().getUser())
				.orElseThrow(NoValidUsersException::new);
	}

	private void buildUsers() {
		getData().getUsers()
				.forEach(
						userData -> {
							this.users.add(new UserModel(userData));
						}
				);
	}

	private void putUnits(AMachineModel machine) throws AThornSecException {
		this.networkUnits.put(machine.getLabel(), machine.getUnits());
	}

	/**
	 * @return the whole network. Be aware that you will have to cast the values
	 *         from this method; you are far better to use one of the specialised
	 *         methods
	 */
	public final Set<AMachineModel> getMachines() {
		return this.machines;
	}

	/**
	 * @param type
	 * @return A map of all machines of a given AMachineModel type, or an empty Set
	 */
	public Set<AMachineModel> getMachines(Class<? extends AMachineModel> type) {
		return getMachines().stream()
				.filter(type::isInstance)
				.map(type::cast)
				.collect(Collectors.toSet());
	}

	/**
	 * @param type
	 * @return A map of all machines of a given type, or an empty Set
	 */
	public Set<AMachineModel> getMachines(AMachineType type) {
		return getMachines().stream()
				.filter(type::equals)
				.collect(Collectors.toSet());
	}

	public final Map<AMachineType, Collection<AMachineModel>> getSubnets() {
		LinkedHashMap<AMachineType, Collection<AMachineModel>> subnets = new LinkedHashMap<>();

		getMachines()
			.stream()
			.map(AMachineModel::getType)
			.filter(distinctByKey(AMachineType::getVLAN))
			.filter(type -> null != type.getVLANSubnet())
			.forEach(type -> {
				subnets.put(
					type,
					getMachines()
						.stream()
						.filter(machine ->
							machine.getType()
								.getVLAN()
								.equals(type.getVLAN())
						)
						.collect(Collectors.toList())
				);
			});

		return subnets;
	}

	static <T> Predicate<T> distinctByKey(Function<? super T, ?> keyExtractor) {
		Map<Object,Boolean> seen = new ConcurrentHashMap<>();
		return t -> seen.putIfAbsent(keyExtractor.apply(t), Boolean.TRUE) == null;
	}

	/**
	 * @return A specific machine model.
	 */
	public final Optional<AMachineModel> getMachineModel(String label) {
		return getMachines().stream()
				.filter(m -> m.getLabel().equalsIgnoreCase(label))
				.findFirst();
	}

	public String getDomain() {
		return getData().getDomain().orElse("lan");
	}

	public Optional<UserModel> getUserModel(String username) {
		return getUsers()
					.stream()
					.filter(u -> u.getUsername().equalsIgnoreCase(username))
					.findFirst();
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
//		for (final AMachineModel server : getMachines(MachineType.SERVER)) {
//			ManageExec exec = null;
//			try {
//				exec = getManageExec(server.getLabel(), "audit", out, quiet);
//			} catch (InvalidServerModelException | IOException e) {
//				// TODO Auto-generated catch block
//				e.printStackTrace();
//			}
//			if (exec != null) {
//				exec.manage();
//			}
//		}
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
		//final OpenKeePassPassphrase pass = new OpenKeePassPassphrase((ServerModel)getMachineModel(server));

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

		//if (pass.isADefaultPassphrase()) {
		//	System.out.println("FAIL: no password in keychain for " + server);
		//	System.out.println("Using the default password instead (this almost certainly won't work!)");
		//	return null;
		//}

		// ManageExec exec = new ManageExec(this.getData().getUser(),
		// pass.getPassphrase(), serverModel.getIP(), this.getData().getSSHPort(server),
		// audit, out);
		//final ManageExec exec = new ManageExec(getMachineModel(server)), this, audit, out);
		return null;
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
}
