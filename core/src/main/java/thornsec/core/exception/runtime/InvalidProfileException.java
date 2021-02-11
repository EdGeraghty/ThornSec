/*
 * This code is part of the ThornSec project.
 *
 * To learn more, please head to its GitHub repo: @privacyint
 *
 * Pull requests encouraged.
 */
package core.exception.runtime;

public class InvalidProfileException extends InvalidMachineModelException {
	private static final long serialVersionUID = 3473443319096462509L;

	public InvalidProfileException(String message) {
		super(message);
	}
}
