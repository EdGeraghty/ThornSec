/*
 * This code is part of the ThornSec project.
 *
 * To learn more, please head to its GitHub repo: @privacyint
 *
 * Pull requests encouraged.
 */
package org.privacyinternational.thornsec.core.model.machine;

import java.io.File;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;
import org.privacyinternational.thornsec.core.data.machine.ServiceData;
import org.privacyinternational.thornsec.core.data.machine.ServerData.GuestOS;
import org.privacyinternational.thornsec.core.data.machine.ServerData;
import org.privacyinternational.thornsec.core.data.machine.configuration.DiskData;
import org.privacyinternational.thornsec.core.data.machine.configuration.DiskData.Format;
import org.privacyinternational.thornsec.core.data.machine.configuration.DiskData.Medium;
import org.privacyinternational.thornsec.core.data.machine.configuration.NetworkInterfaceData;
import org.privacyinternational.thornsec.core.exception.AThornSecException;
import org.privacyinternational.thornsec.core.exception.data.machine.configuration.disks.DiskModelException;
import org.privacyinternational.thornsec.core.exception.data.machine.configuration.disks.InvalidDiskSizeException;
import org.privacyinternational.thornsec.core.exception.runtime.InvalidMachineModelException;
import org.privacyinternational.thornsec.core.iface.IUnit;
import org.privacyinternational.thornsec.core.model.machine.configuration.disks.ADiskModel;
import org.privacyinternational.thornsec.core.model.machine.configuration.disks.DVDModel;
import org.privacyinternational.thornsec.core.model.machine.configuration.disks.HardDiskModel;
import org.privacyinternational.thornsec.core.model.machine.configuration.networking.DHCPClientInterfaceModel;
import org.privacyinternational.thornsec.core.model.network.NetworkModel;

/**
 * This model represents a Service on our network.
 *
 * A service is a machine which is run on a HyperVisor
 */
public class ServiceModel extends ServerModel {

	private Map<String, ADiskModel> disks;
	private ServerModel hypervisor;

	private static final Integer DEFAULT_BOOT_DISK_SIZE = (8 * 1024); //8GB
	private static final Integer DEFAULT_DATA_DISK_SIZE = (20 * 1024); //20GB

	public ServiceModel(ServerData myData, NetworkModel networkModel)
			throws AThornSecException {
		super(myData, networkModel);

		if (null == this.getNetworkInterfaces()) {
			final DHCPClientInterfaceModel nic = new DHCPClientInterfaceModel(new NetworkInterfaceData("eth0"), networkModel);
			this.addNetworkInterface(nic);
		}
	}

	@Override
	public GuestOS getOS() {
		return getData().getOS()
						.orElse(GuestOS.ALPINE_64);
	}

	@Override
	public void init() throws AThornSecException {
		super.init();

		this.hypervisor = (ServerModel) getNetworkModel()
											.getMachineModel(
													getData()
														.getHypervisor()
														.getLabel()
											)
											.orElseThrow();

		initDisks();
	}

	/**
	 * Initialise our disks, making sure there's at least a boot disk and a data
	 * disk.
	 * 
	 * @throws DiskModelException
	 */
	private void initDisks() throws DiskModelException {
		if (getData().getDisks().isPresent()) {
			for (DiskData diskData : getData().getDisks().get().values()) {
				if (diskData.getMedium().isPresent() && diskData.getMedium().get().equals(Medium.DVD)) {
					addDisk(new DVDModel(diskData, getNetworkModel()));
				}
				else {
					addDisk(new HardDiskModel(diskData, getNetworkModel()));
				}
			}
		}

		if (getDisk("boot").isEmpty()) {
			HardDiskModel bootDisk = new HardDiskModel("boot", new File("/disks/boot/" + getLabel() + "/boot.vmdk"));
			addDisk(new HardDiskModel("boot", bootDiskPath));
		}
		if (getDisk("data").isEmpty()) {
			File dataDiskPath = new File("/disks/data/" + getLabel() + "/data.vmdk");
			addDisk(new HardDiskModel("data", dataDiskPath));
		}
	}

	public ServerModel getHypervisor() throws InvalidMachineModelException {
		return this.hypervisor;
	}

	public void addDisk(ADiskModel disk) {
		if (this.disks == null) {
			this.disks = new LinkedHashMap<>();
		}

		this.disks.put(disk.getLabel(), disk);
	}

	public Map<String, ADiskModel> getDisks() {
		return this.disks;
	}

	public Optional<ADiskModel> getDisk(String label) {
		if (getDisks() == null || !getDisks().containsKey(label)) {
			return Optional.empty();
		}
		return Optional.of(getDisks().get(label));
	}

	@Override
	public ServiceData getData() {
		return (ServiceData) super.getData();
	}

	/**
	 * Get the amount of RAM allocated to this machine
	 * @return optionally the amount of RAM in MB, or 2048 if not set
	 */
	public Integer getRAM() {
		return getData().getRAM()
						.orElse(2048);
	}

	/**
	 * Get the CPU execution cap for this machine
	 * @return optionally the execution cap in %, or 100 if not set
	 */
	public Integer getCPUExecutionCap() {
		return getData().getCPUExecutionCap()
						.orElse(100);
	}

	public Collection<? extends IUnit> getUserPasswordUnits() {
		// TODO Auto-generated method stub
		return new ArrayList<>();
	}
}
