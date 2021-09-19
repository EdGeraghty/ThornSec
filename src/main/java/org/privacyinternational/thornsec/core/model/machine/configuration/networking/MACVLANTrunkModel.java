/*
 * This code is part of the ThornSec project.
 *
 * To learn more, please head to its GitHub repo: @privacyint
 *
 * Pull requests encouraged.
 */
package org.privacyinternational.thornsec.core.model.machine.configuration.networking;

import org.privacyinternational.thornsec.core.data.machine.configuration.NetworkInterfaceData;
import org.privacyinternational.thornsec.core.data.machine.configuration.NetworkInterfaceData.Inet;
import org.privacyinternational.thornsec.core.data.machine.configuration.NetworkInterfaceData.Direction;
import org.privacyinternational.thornsec.core.exception.data.InvalidIPAddressException;
import org.privacyinternational.thornsec.core.exception.data.machine.configuration.InvalidNetworkInterfaceException;
import org.privacyinternational.thornsec.core.model.network.NetworkModel;
import org.privacyinternational.thornsec.core.unit.fs.FileUnit;

import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.Optional;
import java.util.Set;

/**
 * This model represents a MACVLAN Trunk - i.e. the "physical" interface upon
 * which to stack the VLANs.
 */
public class MACVLANTrunkModel extends NetworkInterfaceModel {
	private final Set<MACVLANModel> vlans;

	public MACVLANTrunkModel(NetworkInterfaceData myData, NetworkModel networkModel) throws InvalidNetworkInterfaceException, InvalidIPAddressException {
		super(myData, networkModel);

		setInet(Inet.MACVLAN);
		setWeighting(10);
		setARP(false);
		setIsIPForwarding(true);
		setIsIPMasquerading(false);
		setReqdForOnline(true);
		setDirection(Direction.NONE);

		vlans = new LinkedHashSet<>();
	}

	@Override
	public Optional<FileUnit> getNetworkFile() {
		//TODO: fix this, it's a hack
		final FileUnit network = super.getNetworkFile().get();

		network.appendCarriageReturn();
		network.appendLine("[Network]");
		getVLANs().forEach(vlan -> {
			network.appendLine("MACVLAN=" + vlan.getIface());
		});

		return Optional.of(network);
	}

	@Override
	public Optional<FileUnit> getNetDevFile() {
		return Optional.empty(); // Don't need a NetDev for a MACVLAN Trunk
	}

	public final void addVLAN(MACVLANModel vlan) {
		this.vlans.add(vlan);
	}

	public final Collection<MACVLANModel> getVLANs() {
		return this.vlans;
	}
}
