/*
 * This code is part of the ThornSec project.
 *
 * To learn more, please head to its GitHub repo: @privacyint
 *
 * Pull requests encouraged.
 */
package core.data.machine;

import java.io.File;
import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.Optional;
import javax.json.JsonObject;

import core.exception.data.ADataException;

/**
 * This class represents a Hypervisor.
 *
 * For our purposes, a Hypervisor is a machine which is running a type-2
 * https://en.wikipedia.org/wiki/Hypervisor
 */
public class HypervisorData extends ServerData {
	private File vmBase;
	private Integer backupFrequency;
	private Collection<ServerData> services;

	public HypervisorData(String label) {
		super(label);

		this.vmBase = null;
		this.backupFrequency = null;
		this.services = new LinkedHashSet<>();
		
		this.putType(MachineType.HYPERVISOR);
	}

	@Override
	public void read(JsonObject data) throws ADataException {
		super.read(data);

		if (data.containsKey("vm_base")) {
			this.vmBase = new File(data.getString("vm_base"));
		}

		if (data.containsKey("backup_frequency")) {
			this.backupFrequency = data.getInt("backup_frequency");
		}
	}

	public final Collection<ServerData> getServices() {
		return this.services;
	}

	public final void addService(ServerData service) {
		this.services.add(service);
	}

	public final Optional<File> getVmBase() {
		return Optional.ofNullable(this.vmBase);
	}

	public final Optional<Integer> getBackupFrequency() {
		return Optional.ofNullable(this.backupFrequency);
	}
}
