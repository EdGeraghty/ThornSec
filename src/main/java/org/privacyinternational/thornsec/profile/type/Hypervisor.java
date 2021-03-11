/*
 * This code is part of the ThornSec project.
 *
 * To learn more, please head to its GitHub repo: @privacyint
 *
 * Pull requests encouraged.
 */
package org.privacyinternational.thornsec.profile.type;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import javax.json.stream.JsonParsingException;
import org.privacyinternational.thornsec.core.data.machine.AMachineData.MachineType;
import org.privacyinternational.thornsec.core.data.machine.configuration.NetworkInterfaceData;
import org.privacyinternational.thornsec.core.data.machine.configuration.NetworkInterfaceData.Direction;
import org.privacyinternational.thornsec.core.data.machine.configuration.DiskData.Medium;
import org.privacyinternational.thornsec.core.exception.AThornSecException;
import org.privacyinternational.thornsec.core.exception.data.ADataException;
import org.privacyinternational.thornsec.core.exception.data.machine.InvalidServerException;
import org.privacyinternational.thornsec.core.exception.runtime.InvalidMachineModelException;
import org.privacyinternational.thornsec.core.iface.IUnit;
import org.privacyinternational.thornsec.core.model.machine.HypervisorModel;
import org.privacyinternational.thornsec.core.model.machine.ServiceModel;
import org.privacyinternational.thornsec.core.model.machine.configuration.disks.ADiskModel;
import org.privacyinternational.thornsec.core.model.machine.configuration.networking.NetworkInterfaceModel;
import org.privacyinternational.thornsec.core.profile.AStructuredProfile;
import org.privacyinternational.thornsec.core.unit.SimpleUnit;
import org.privacyinternational.thornsec.core.unit.fs.DirUnit;
import org.privacyinternational.thornsec.core.unit.fs.FileChecksumUnit;
import org.privacyinternational.thornsec.core.unit.fs.FileChecksumUnit.Checksum;
import org.privacyinternational.thornsec.core.unit.fs.FileDownloadUnit;
import org.privacyinternational.thornsec.core.unit.pkg.InstalledUnit;
import org.privacyinternational.thornsec.profile.HypervisorScripts;
import org.privacyinternational.thornsec.profile.hypervisor.AHypervisorProfile;
import org.privacyinternational.thornsec.profile.hypervisor.Virtualbox;

/**
 * This is the representation of your HyperVisor itself.
 * 
 * These are things which should be done on a HyperVisor machine, regardless of
 * what hypervisor layer it's actually running
 */
public class Hypervisor extends AStructuredProfile {

	private final AHypervisorProfile virtualbox;
	private final HypervisorScripts scripts;

	private Set<ServiceModel> services;

	/**
	 * Create a new HyperVisor box, with initialised NICs, and initialise the
	 * virtualisation layer itself, including the building of Service machines
	 * 
	 * @throws JsonParsingException
	 * @throws ADataException
	 * @throws InvalidMachineModelException 
	 */
	public Hypervisor(HypervisorModel me) throws JsonParsingException, ADataException, InvalidMachineModelException {
		super(me);

		this.virtualbox = new Virtualbox(me);
		this.scripts = new HypervisorScripts(me);

		addServices();
	}

	private void addServices() throws InvalidMachineModelException {
		this.services = getServerModel().getServices();
	}

	public Set<ServiceModel> getServices() {
		return this.services;
	}

	@Override
	public Collection<IUnit> getInstalled() throws AThornSecException {
		final Collection<IUnit> units = new ArrayList<>();

		units.addAll(this.virtualbox.getInstalled());
		units.addAll(this.scripts.getInstalled());

		units.add(new DirUnit("thornsec_base_dir", "proceed", getServerModel().getVMBase().getAbsolutePath()));

		units.add(new InstalledUnit("whois", "proceed", "whois"));
		units.add(new InstalledUnit("tmux", "proceed", "tmux"));
		units.add(new InstalledUnit("socat", "proceed", "socat"));

		return units;
	}

	@Override
	public Collection<IUnit> getPersistentConfig() throws AThornSecException {
		final Collection<IUnit> units = new ArrayList<>();

		units.addAll(this.virtualbox.getPersistentConfig());
		units.addAll(this.scripts.getPersistentConfig());

		return units;
	}

	@Override
	public Collection<IUnit> getPersistentFirewall() throws AThornSecException {
		final Collection<IUnit> units = new ArrayList<>();

		units.addAll(this.virtualbox.getPersistentFirewall());
		units.addAll(this.scripts.getPersistentFirewall());

		return units;
	}

	private String getNetworkBridge() {
		if (getMachineModel().isType(MachineType.ROUTER)) {
			return MachineType.SERVER.toString();
		}

		return getMachineModel().getNetworkInterfaces()
					.stream()
					.filter(nic -> Direction.LAN.equals(nic.getDirection()))
					.findAny()
					.get()
					.getIface();
	}

	@Override
	public Collection<IUnit> getLiveConfig() throws AThornSecException {
		final Collection<IUnit> units = new ArrayList<>();

		getServices().forEach(service -> {
			units.addAll(service.getUserPasswordUnits());
			units.addAll(virtualbox.buildVM(service));
		});
		
		//units.addAll(this.hypervisor.getLiveConfig());
		units.addAll(this.scripts.getLiveConfig());

		return units;
	}

	private Collection<IUnit> getDisksFormattedUnits(String service) throws InvalidMachineModelException {
		final Collection<IUnit> units = new ArrayList<>();

		((ServiceModel)getNetworkModel().getMachineModel(service)).getDisks().forEach((label, disk) -> {
			// For now, do all this as root. We probably want to move to another user, idk
			units.add(new SimpleUnit(service + "_" + label + "_disk_formatted", "proceed",
					"", //No config to do here
					"sudo bash -c 'export LIBGUESTFS_BACKEND_SETTINGS=force_tcg;" + "virt-filesystems -a " + disk.getFilename() + "'", "", "fail",
					service + "'s " + label + " disk is unformatted, please configure the service and try mounting again."));
		});

		return units;
	}

	private Collection<IUnit> getDiskLoopbackUnits(String service) throws InvalidMachineModelException {
		final Collection<IUnit> units = new ArrayList<>();

		for (ADiskModel disk : ((ServiceModel)getNetworkModel().getMachineModel(service)).getDisks().values().stream().filter(disk -> disk.getMedium() == Medium.DISK).toArray(ADiskModel[]::new)) {
			// For now, do all this as root. We probably want to move to another user, idk

			units.add(new SimpleUnit(service + "_" + disk.getLabel() + "_disk_loopback_mounted", service + "_" + disk.getLabel() + "_disk_formatted",
					"sudo bash -c '" + " export LIBGUESTFS_BACKEND_SETTINGS=force_tcg;" + " guestmount -a " + disk.getFilename() + " -i" // Inspect the disk for the relevant partition
							+ " -o direct_io" // All read operations must be done against live, not cache
							+ " --ro" // _MOUNT THE DISK READ ONLY_
							+ " " + disk.getFilePath() + "/live/" + "'",
					"sudo mount | grep " + disk.getFilePath(), "", "fail",
					"I was unable to loopback mount the " + disk.getLabel() + " disk for " + service + " in " + getMachineModel().getLabel() + "."));
		}

		return units;
	}

	@Override
	public HypervisorModel getServerModel() {
		return (HypervisorModel) super.getServerModel();
	}
}
