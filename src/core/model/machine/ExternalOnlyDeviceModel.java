/*
 * This code is part of the ThornSec project.
 *
 * To learn more, please head to its GitHub repo: @privacyint
 *
 * Pull requests encouraged.
 */
package core.model.machine;

import javax.mail.internet.AddressException;

import core.exception.data.machine.InvalidMachineException;
import core.model.network.NetworkModel;

/**
 * This model represents an "External-Only" device on our network.
 *
 * An external-only device is one which can access the wider internet, but is
 * not allowed to access internal services.
 */
public class ExternalOnlyDeviceModel extends ADeviceModel {
	public ExternalOnlyDeviceModel(String label, NetworkModel networkModel)
			throws InvalidMachineException, AddressException {
		super(label, networkModel);
	}
}
