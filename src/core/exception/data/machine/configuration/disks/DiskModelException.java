/*
 * This code is part of the ThornSec project.
 *
 * To learn more, please head to its GitHub repo: @privacyint
 *
 * Pull requests encouraged.
 */
package core.exception.data.machine.configuration.disks;

import core.exception.data.ADataException;

public class DiskModelException extends ADataException {
	private static final long serialVersionUID = -4978682429685931190L;

	public DiskModelException(String message) {
		super(message);
	}
}
