/*
 * This code is part of the ThornSec project.
 *
 * To learn more, please head to its GitHub repo: @privacyint
 *
 * Pull requests encouraged.
 */
package core.exception.runtime;

import core.exception.AThornSecException;

public abstract class ARuntimeException extends AThornSecException {
	private static final long serialVersionUID = 7533173446854104304L;

	public ARuntimeException(String message) {
		super(message);
	}
}
