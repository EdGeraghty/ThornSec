/*
 * This code is part of the ThornSec project.
 * 
 * To learn more, please head to its GitHub repo: @privacyint
 * 
 * Pull requests encouraged.
 */
package org.privacyinternational.thornsec.core.data.machine;

import javax.json.JsonObject;

import org.privacyinternational.thornsec.core.exception.data.ADataException;

import java.nio.file.Path;

/**
 * Represents an internal-only device on our network.
 * 
 * This is a device which is allowed to *respond* to our Users, but
 * shouldn't be able to talk to the wider Internet.
 * 
 * Why is this important? Ask NASA.
 * https://www.zdnet.com/article/nasa-hacked-because-of-unauthorized-raspberry-pi-connected-to-its-network/
 */
public class InternalDeviceData extends ADeviceData {

	public InternalDeviceData(String label) {
		super(label);
	}

	@Override
	public InternalDeviceData read(JsonObject data, Path configFilePath) throws ADataException {
		super.read(data, configFilePath);

		return this;
	}
}
