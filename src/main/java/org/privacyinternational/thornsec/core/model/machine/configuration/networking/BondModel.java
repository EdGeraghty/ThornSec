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
import org.privacyinternational.thornsec.core.exception.data.InvalidIPAddressException;
import org.privacyinternational.thornsec.core.exception.data.machine.configuration.InvalidNetworkInterfaceException;
import org.privacyinternational.thornsec.core.model.network.NetworkModel;
import org.privacyinternational.thornsec.core.unit.fs.FileUnit;

import java.util.Optional;

/**
 * This model represents a Bond. You have to stack this on top of a Trunk for it
 * to work, of course.
 */
public class BondModel extends NetworkInterfaceModel {
	public BondModel(NetworkInterfaceData myData, NetworkModel networkModel) throws InvalidNetworkInterfaceException, InvalidIPAddressException {
		super(myData, networkModel);
		
		super.setInet(Inet.BOND);
		super.setWeighting(0);

		super.addToNetDev(Section.BOND, "Mode", "802.3ad");
	}

	@Override
	public Optional<FileUnit> getNetworkFile() {
		return Optional.empty(); // Don't need a Network for a Bond
	}
}
