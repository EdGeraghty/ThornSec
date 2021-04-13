/*
 * This code is part of the ThornSec project.
 *
 * To learn more, please head to its GitHub repo: @privacyint
 *
 * Pull requests encouraged.
 */
package org.privacyinternational.thornsec.type;

import org.privacyinternational.thornsec.core.model.machine.ServerModel;

/**
 * This is a dedicated server on your network. This is something ThornSec needs
 * to know about, but shouldn't attempt to configure
 */
public class Dedicated extends AMachineType {

	public Dedicated(ServerModel me)  {
		super(me);
	}

}
