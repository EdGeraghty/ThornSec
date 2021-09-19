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
 * This model represents a dummy interface. This is the networking equivalent of
 * /dev/null.
 *
 * Use this interface where you need a trunk but don't have a "real" NIC spare
 */
public class DummyModel extends NetworkInterfaceModel {
	public DummyModel(NetworkInterfaceData myData, NetworkModel networkModel) throws InvalidNetworkInterfaceException, InvalidIPAddressException {
		super(myData, networkModel);

		setInet(Inet.DUMMY);
		setWeighting(10);
	}

	@Override
	public Optional<FileUnit> getNetworkFile() {
		return Optional.empty(); // Don't need a Network for a dummy interface
	}
}
