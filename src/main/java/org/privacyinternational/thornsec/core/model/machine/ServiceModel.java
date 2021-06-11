/*
 * This code is part of the ThornSec project.
 *
 * To learn more, please head to its GitHub repo: @privacyint
 *
 * Pull requests encouraged.
 */
package org.privacyinternational.thornsec.core.model.machine;

import inet.ipaddr.AddressStringException;
import inet.ipaddr.IncompatibleAddressException;
import inet.ipaddr.MACAddressString;
import inet.ipaddr.mac.MACAddress;
import org.privacyinternational.thornsec.core.data.machine.ServerData;
import org.privacyinternational.thornsec.core.data.machine.ServiceData;
import org.privacyinternational.thornsec.core.data.machine.configuration.DiskData;
import org.privacyinternational.thornsec.core.data.machine.configuration.HardDiskData;
import org.privacyinternational.thornsec.core.data.machine.configuration.NetworkInterfaceData;
import org.privacyinternational.thornsec.core.exception.AThornSecException;
import org.privacyinternational.thornsec.core.exception.data.ADataException;
import org.privacyinternational.thornsec.core.exception.data.machine.configuration.disks.ADiskDataException;
import org.privacyinternational.thornsec.core.iface.IUnit;
import org.privacyinternational.thornsec.core.model.machine.configuration.disks.ADiskModel;
import org.privacyinternational.thornsec.core.model.machine.configuration.disks.DVDModel;
import org.privacyinternational.thornsec.core.model.machine.configuration.disks.HardDiskModel;
import org.privacyinternational.thornsec.core.model.machine.configuration.networking.StaticInterfaceModel;
import org.privacyinternational.thornsec.core.model.network.NetworkModel;
import org.privacyinternational.thornsec.profile.guest.AOS;
import org.privacyinternational.thornsec.profile.guest.Alpine;

import javax.json.Json;
import java.io.File;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;

/**
 * This model represents a Service on our network.
 *
 * A service is a machine which is run on a HyperVisor
 */
public class ServiceModel extends ServerModel {

	private Map<String, ADiskModel> disks;
	private final ServerModel hypervisor;

	private static final Integer DEFAULT_BOOT_DISK_SIZE = (8 * 1024); //8GB
	private static final Integer DEFAULT_DATA_DISK_SIZE = (20 * 1024); //20GB

	public ServiceModel(ServerData myData, NetworkModel networkModel) throws AThornSecException {
		super(myData, networkModel);

		this.hypervisor = (ServerModel) getNetworkModel()
				.getMachineModel(
						getData()
								.getHypervisor()
								.getLabel()
				)
				.orElseThrow();

		if (getNetworkInterfaces().isEmpty()) {
			StaticInterfaceModel nic = new StaticInterfaceModel(
					new NetworkInterfaceData(
							"eth0",
							null,
							Json.createObjectBuilder().build()
					),
					null
			);

			nic.setMac(generateMAC("eth0"));
			nic.setDirection(NetworkInterfaceData.Direction.LAN);

			addNetworkInterface(nic);
		}

		initDisks();
	}

	@Override
	public AOS getOS() throws AThornSecException {
		if (getData().getOS().isEmpty()) {
			return new Alpine(this);
		}

		return super.getOS();
	}

	/**
	 * Initialise our disks, making sure there's at least a boot disk and a data
	 * disk.
	 * 
	 * @throws ADiskDataException
	 */
	private void initDisks() throws ADataException {
		if (getData().getDisks().isPresent()) {
			for (DiskData diskData : getData().getDisks().get().values()) {
				if (diskData instanceof HardDiskData) {
					addDisk(new HardDiskModel((HardDiskData) diskData, getNetworkModel()));
				}
				else {
					addDisk(new DVDModel(diskData, getNetworkModel()));
				}
			}
		}

		if (getDisk("boot").isEmpty()) {
			HardDiskModel bootDisk = new HardDiskModel("boot", new File("/disks/boot/" + getLabel() + "/boot.vmdk"));

			bootDisk.setSize(DEFAULT_BOOT_DISK_SIZE);
			bootDisk.setComment("Autogenerated boot disk");

			addDisk(bootDisk);
		}
		if (getDisk("data").isEmpty()) {
			File dataDiskPath = new File("/disks/data/" + getLabel() + "/data.vmdk");
			addDisk(new HardDiskModel("data", dataDiskPath));
		}
	}

	public ServerModel getHypervisor() {
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

	public Collection<IUnit> getUserPasswordUnits() {
		// TODO Auto-generated method stub
		return new ArrayList<>();
	}

	public MACAddress generateMAC(String iface) {
		final String name = getLabel() + iface;

		MessageDigest md = null;
		try {
			md = MessageDigest.getInstance("SHA-512");
		} catch (final NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		assert md != null;
		md.update(name.getBytes());

		final byte[] byteData = md.digest();
		final StringBuilder hashCodeBuffer = new StringBuilder();
		for (final byte element : byteData) {
			hashCodeBuffer.append(Integer.toString((element & 0xff) + 0x100, 16).substring(1));

			if (hashCodeBuffer.length() == 6) {
				break;
			}
		}

		final String address = "080027" + hashCodeBuffer;

		try {
			return new MACAddressString(address).toAddress();
		} catch (final AddressStringException | IncompatibleAddressException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		return null;
	}
}
