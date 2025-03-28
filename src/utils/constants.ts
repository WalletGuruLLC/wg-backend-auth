export const HttpStatus = {
	OK: 200,
	CREATED: 201,
	ACCEPTED: 202,
	NO_CONTENT: 204,
	BAD_REQUEST: 400,
	UNAUTHORIZED: 401,
	FORBIDDEN: 403,
	NOT_FOUND: 404,
	INTERNAL_SERVER_ERROR: 500,
	BAD_GATEWAY: 502,
	SERVICE_UNAVAILABLE: 503,
};

export const StatusMessages = {
	[HttpStatus.OK]: 'success',
	[HttpStatus.CREATED]: 'created',
	[HttpStatus.ACCEPTED]: 'accepted',
	[HttpStatus.NO_CONTENT]: 'no content',
	[HttpStatus.BAD_REQUEST]: 'bad request',
	[HttpStatus.UNAUTHORIZED]: 'unauthorized',
	[HttpStatus.FORBIDDEN]: 'forbidden',
	[HttpStatus.NOT_FOUND]: 'not found',
	[HttpStatus.INTERNAL_SERVER_ERROR]: 'internal server error',
	[HttpStatus.BAD_GATEWAY]: 'bad gateway',
	[HttpStatus.SERVICE_UNAVAILABLE]: 'service unavailable',
};

export const errorCodes = {
	WGE0001: {
		message: 'Invalid credentials',
		description: 'There is an issue with your credentials, please try again',
		descriptionEs:
			'Ha ocurrido un problema con sus credenciales, por favor intentelo de nuevo',
	},
	WGE0002: {
		message: 'User not found',
		description:
			'There is no account associated with the entered email or username.',
		descriptionEs:
			'No existe una cuenta asociada con el correo electrónico o nombre de usuario ingresado.',
	},
	WGE0003: {
		message: 'User already exists',
		description:
			'An account is already registered with the provided email or username.',
		descriptionEs:
			'Ya existe una cuenta registrada con el correo electrónico o nombre de usuario proporcionado.',
	},
	WGE0004: {
		message: 'Email not verified',
		description: 'The account exists, but the email has not been verified.',
		descriptionEs:
			'La cuenta existe, pero el correo electrónico no ha sido verificado.',
	},
	WGE0005: {
		message: 'Incorrect verification code',
		description: 'The entered verification code is incorrect or has expired.',
		descriptionEs:
			'El código de verificación ingresado es incorrecto o ha expirado.',
	},
	WGE0006: {
		message: 'Session expired',
		description: 'The authentication session has expired, please log in again.',
		descriptionEs:
			'La sesión de autenticación ha expirado, por favor inicie sesión nuevamente.',
	},
	WGE0007: {
		message: 'Incorrect old password',
		description: 'The current password entered is incorrect.',
		descriptionEs: 'La contraseña actual ingresada es incorrecta.',
	},
	WGE0008: {
		message: 'New password not valid',
		description:
			'The new password does not meet the established security requirements.',
		descriptionEs:
			'La nueva contraseña no cumple con los requisitos de seguridad establecidos.',
	},
	WGE0010: {
		message: 'Error sending verification email',
		description:
			'There was a problem sending the verification email. Please try again.',
		descriptionEs:
			'Hubo un problema al enviar el correo de verificación. Por favor, inténtelo de nuevo.',
	},
	WGE0011: {
		message: 'Invalid reset token',
		description: 'The entered password reset token is invalid or has expired.',
		descriptionEs:
			'El token de restablecimiento de contraseña ingresado es inválido o ha expirado.',
	},
	WGE0015: {
		message: 'Two-factor authentication error',
		description:
			'Two-factor authentication failed due to an incorrect code or technical issue.',
		descriptionEs:
			'La autenticación de dos factores falló debido a un código incorrecto o un problema técnico.',
	},
	WGE0016: {
		message: 'Internal server error',
		description:
			'An unexpected error occurred on the server. Please try again later.',
		descriptionEs:
			'Ocurrió un error inesperado en el servidor. Por favor, inténtelo de nuevo más tarde.',
	},
	WGE0017: {
		message: 'Invalid user type',
		description: 'The type of user entered is invalid or does not correspond.',
		descriptionEs: 'El tipo de usuario ingresado es inválido o no corresponde.',
	},
	WGE00018: {
		message: 'Incomplete information',
		description:
			'The provided information is incomplete or missing required details.',
		descriptionEs:
			'La información proporcionada está incompleta o falta algún dato requerido.',
	},
	WGE00019: {
		message: 'Invalid request',
		description: 'The request contains invalid or unsupported data.',
		descriptionEs: 'La solicitud contiene datos inválidos o no admitidos.',
	},
	WGE00020: {
		message: 'Operation failed',
		description:
			'An error occurred during the operation. Please try again later.',
		descriptionEs:
			'Ocurrió un error durante la operación. Por favor, intente nuevamente más tarde.',
	},
	WGE0021: {
		message: 'Invalid access token',
		description:
			'The provided access token is invalid or has expired. Please provide a valid token and try again.',
		descriptionEs:
			'El token de acceso proporcionado es inválido o ha expirado. Por favor, proporcione un token válido e inténtelo de nuevo.',
	},
	WGE0070: {
		message: 'Failed to send OTP email',
		description:
			'There was an error while sending the OTP email. Please try again.',
		descriptionEs:
			'Hubo un error al enviar el correo electrónico con el OTP. Por favor, inténtelo de nuevo.',
	},
	WGE0022: {
		message: 'Inactive user',
		description: 'The user is inactive.',
		descriptionEs: 'El usuario se encuentra inactivo.',
	},
	WGE0023: {
		message: 'Invalid page',
		description: 'The page is invalid.',
		descriptionEs: 'La pagina es invalida.',
	},
	WGE0024: {
		message: 'Email update not allowed',
		description:
			'The account has already been validated, email update is not permitted.',
		descriptionEs:
			'La cuenta ya ha sido validada, no se permite la actualización del correo electrónico.',
	},
	WGE0025: {
		message: 'Add role failed',
		description: 'Failed to add role. Check info and retry.',
		descriptionEs:
			'Error al agregar el rol. Verifique la información y vuelva a intentarlo.',
	},
	WGE0026: {
		message: 'Edit role failed',
		description: 'Failed to edit role. Check inputs, then retry.',
		descriptionEs:
			'Error al editar el rol. Verifica los datos e inténtalo de nuevo.',
	},
	WGE0027: {
		message: 'Role not found',
		description: 'There is no role with the id provided',
		descriptionEs: 'No hay ningún rol asociado con el id ingresado.',
	},
	WGE0032: {
		message: `Doesn't exist roles`,
		description: `You haven't created any roles yet. Please click 'Add New Role' to get started`,
		descriptionEs: `Aún no has creado ningún rol. Por favor, haz clic en 'Agregar Nuevo Rol' para comenzar`,
	},
	WGE0033: {
		message: `Role not found`,
		description: `The role you are looking for does not exist. Please verify the role ID.`,
		descriptionEs: `El rol que estás buscando no existe. Por favor, verifica el ID del rol.`,
	},
	WGE0034: {
		message: `No access levels found`,
		description: `No access levels were found for the specified role. Please check the role ID.`,
		descriptionEs: `No se encontraron niveles de acceso para el rol especificado. Por favor, verifica el ID del rol.`,
	},
	WGE0035: {
		message: `Failed to update access level`,
		description: `An error occurred while trying to update the access level. Please try again later.`,
		descriptionEs: `Se produjo un error al intentar actualizar el nivel de acceso. Por favor, inténtelo de nuevo más tarde.`,
	},
	WGE0036: {
		message: `Failed to create access level`,
		description: `An error occurred while trying to create the access level. Please try again later.`,
		descriptionEs: `Se produjo un error al intentar crear el nivel de acceso. Por favor, inténtelo de nuevo más tarde.`,
	},
	WGE0037: {
		message: `No modules available`,
		description: `There are no modules available to update for the specified role.`,
		descriptionEs: `No hay módulos disponibles para actualizar para el rol especificado.`,
	},
	WGE0038: {
		message: `No permission to perform this action`,
		description: `You do not have permission to perform this action.`,
		descriptionEs: `No tienes permiso para realizar esta acción.`,
	},
	WGE0039: {
		message: `No permission in the specified module`,
		description: `You do not have permission in the specified module.`,
		descriptionEs: `No tienes permisos en el módulo especificado.`,
	},
	WGE0040: {
		message: `User not found`,
		description: `There is no user with the id provided.`,
		descriptionEs: `No hay ningún usuário asociado con el id ingresado.`,
	},
	WGE0041: {
		message: 'Edit provider failed',
		description: 'Failed to edit provider. Check inputs, then retry.',
		descriptionEs:
			'Error al editar el proveedor. Verifica los datos e inténtalo de nuevo.',
	},
	WGE0042: {
		message: 'Delete provider failed',
		description: 'Failed to delete provider. Check inputs, then retry.',
		descriptionEs:
			'Error al eliminar el proveedor. Verifica los datos e inténtalo de nuevo.',
	},
	WGE0043: {
		message: `Failed to create provider`,
		description: `An error occurred while trying to create the provider. Please try again later.`,
		descriptionEs: `Se produjo un error al intentar crear el proveedor. Por favor, inténtelo de nuevo más tarde.`,
	},
	WGE00044: {
		message: 'Invalid phone format',
		description: 'The provided phone is invalid.',
		descriptionEs: 'El telefono proporcionada es invalido.',
	},
	WGE0045: {
		message: `Module not found`,
		description: `The specified module does not exist in the system.`,
		descriptionEs: `El módulo especificado no existe en el sistema.`,
	},
	WGE0046: {
		message: `Role not found`,
		description: `The specified role does not exist in the system.`,
		descriptionEs: `El rol especificado no existe en el sistema.`,
	},
	WGE0047: {
		message: `Module not found in role`,
		description: `The specified module does not exist within the specified role.`,
		descriptionEs: `El módulo especificado no existe dentro del rol especificado.`,
	},
	WGE0048: {
		message: 'Invalid email',
		description: 'The entered email is invalid.',
		descriptionEs: 'El correo electronico ingresado es inválido.',
	},
	WGE0049: {
		message: 'Invalid access level',
		description: 'The entered access level is invalid.',
		descriptionEs: 'El nivel de acceso ingresado es inválido.',
	},
	WGE0050: {
		message: 'Edit User failed',
		description: 'Failed to edit user. Check inputs, then retry.',
		descriptionEs:
			'Error al editar el usuario. Verifica los datos e inténtalo de nuevo.',
	},
	WGE00108: {
		message: 'Login inactive User',
		description:
			'This email is currently inactive. Please contact the wallet guru support team to reactivate your account.',
		descriptionEs:
			'Este correo electrónico está actualmente inactivo. Por favor, contacta al equipo de soporte de Wallet Guru para reactivar tu cuenta.',
	},
};

export const successCodes = {
	WGE0009: {
		message: 'Password changed successfully',
		description: 'The password has been changed successfully.',
		descriptionEs: 'La contraseña ha sido cambiada con éxito.',
	},
	WGE0012: {
		message: 'Password reset successfully',
		description: 'The password has been reset successfully.',
		descriptionEs: 'La contraseña ha sido restablecida con éxito.',
	},
	WGE0013: {
		message: 'User registered successfully',
		description:
			'The user has been registered successfully. A verification email has been sent.',
		descriptionEs:
			'El usuario ha sido registrado con éxito. Se ha enviado un correo de verificación.',
	},
	WGE0014: {
		message: 'Login successful',
		description: 'The user has logged in successfully.',
		descriptionEs: 'El usuario ha iniciado sesión con éxito.',
	},
	WGE0018: {
		message: 'Success sending verification email',
		description: 'The verification code was sent successfully.',
		descriptionEs: 'El código de verificación fue enviado con éxito.',
	},
	WGE0019: {
		message: 'Success getting users',
		description: 'The users was getting succesfully.',
		descriptionEs: 'Los usuarios se han obtenido con éxito.',
	},
	WGE0020: {
		message: 'User updated successfully',
		description: 'The user information has been updated successfully.',
		descriptionEs: 'La información del usuario ha sido actualizada con éxito.',
	},
	WGE0021: {
		message: 'User deleted successfully',
		description: 'The user has been deleted successfully.',
		descriptionEs: 'El usuario ha sido eliminado con éxito.',
	},
	WGE0022: {
		message: 'Successfully returned user info',
		description: 'The user`s information has been successfully obtained.',
		descriptionEs: 'La información del usuario se ha obtenido con éxito.',
	},
	WGS0023: {
		message: 'Add role successful',
		description: 'The role has been added successfully.',
		descriptionEs: 'El rol ha sido añadido con éxito.',
	},
	WGS0024: {
		message: 'Edit role successful',
		description: 'The role has been edited successfully.',
		descriptionEs: 'El rol ha sido editado con éxito.',
	},
	WGS0031: {
		message: 'Success getting roles',
		description: 'The roles was getting succesfully.',
		descriptionEs: 'Los roles se han obtenido con éxito.',
	},
	WGE0071: {
		message: 'OTP email sent successfully',
		description: 'The OTP email has been sent successfully.',
		descriptionEs:
			'El correo electrónico con el OTP ha sido enviado con éxito.',
	},
	WGE0072: {
		message: 'Logout successful',
		description: 'The user has been logged out successfully.',
		descriptionEs: 'El usuario ha cerrado sesión con éxito.',
	},
	WGE0073: {
		message: 'Success getting providers',
		description: 'The providers was getting succesfully.',
		descriptionEs: 'Los proveedores se han obtenido con éxito.',
	},
	WGE0074: {
		message: 'Success getting provider',
		description: 'The provider was getting succesfully.',
		descriptionEs: 'El proveedor se han obtenido con éxito.',
	},
	WGE0075: {
		message: 'Edit provider successful',
		description: 'The provider has been edited successfully.',
		descriptionEs: 'El proveedor ha sido editado con éxito.',
	},
	WGE0076: {
		message: 'Provider deleted successfully',
		description: 'The provider has been deleted successfully.',
		descriptionEs: 'El proveedor ha sido eliminado con éxito.',
	},
	WGS0077: {
		message: 'Add provider successful',
		description: 'The provider has been added successfully.',
		descriptionEs: 'El proveedor ha sido añadido con éxito.',
	},
	WGE0078: {
		message: 'Validate access successful',
		description: 'Validate access successfully.',
		descriptionEs: 'Acceso validado con éxito.',
	},
	WGE0079: {
		message: 'Access level updated successfully',
		description: 'The access leve has been updated successfully.',
		descriptionEs:
			'La información del nivel de acceso ha sido actualizada con éxito.',
	},
	WGE0080: {
		message: 'Add access level successfully',
		description: 'The access level has been added successfully.',
		descriptionEs: 'El nivel de acceso ha sido añadido con éxito.',
	},
	WGE0081: {
		message: 'Success getting access levels',
		description: 'The access levels was getting succesfully.',
		descriptionEs: 'Los niveles de acceso se han obtenido con éxito.',
	},
	WGS0082: {
		message: 'Success getting role',
		description: 'The role was getting succesfully.',
		descriptionEs: 'El role se ha obtenido con éxito.',
	},
	WGE0083: {
		message: 'Edit user successful',
		description: 'The user has been edited successfully.',
		descriptionEs: 'El usuario ha sido editado con éxito.',
	},
};

export const licenseFormats = {
	Alabama: /^\d{7}$/,
	Alaska: /^[A-Z]\d{6}$/,
	Arizona: /^[A-Z]\d{8}$/,
	Arkansas: /^\d{8}$/,
	California: /^[A-Z]\d{7}$/,
	Colorado: /^\d{9}$|^[A-Z]\d{3}[A-Z]{3}\d{2}$/,
	Connecticut: /^\d{9}$/,
	Delaware: /^\d{1,7}$/,
	Florida: /^[A-Z]\d{12}$/,
	Georgia: /^\d{9}$/,
	Hawaii: /^[A-Z]{1,2}\d{8}$/,
	Idaho: /^\d{9}$|^[A-Z]{2}\d{6}$/,
	Illinois: /^[A-Z]\d{11}$/,
	Indiana: /^\d{10}$|^[A-Z]\d{9}$/,
	Iowa: /^\d{9}$|^[A-Z]{3}\d{6}$/,
	Kansas: /^\d{9}$|^[A-Z]\d{8}$/,
	Kentucky: /^[A-Z]\d{8}$/,
	Louisiana: /^[A-Z]\d{8}$/,
	Maine: /^\d{7}$|^\d{7}[A-Z]$/,
	Maryland: /^[A-Z]\d{12}$/,
	Massachusetts: /^\d{9}$/,
	Michigan: /^[A-Z]\d{12}$/,
	Minnesota: /^[A-Z]\d{12}$/,
	Mississippi: /^\d{9}$/,
	Missouri: /^[A-Z]\d{5,9}$/,
	Montana: /^\d{13}$/,
	Nebraska: /^[A-Z]\d{8,9}$/,
	Nevada: /^\d{9}$|^\d{12}$/,
	'New Hampshire': /^[A-Z]{2}\d{3,5}[A-Z]$/,
	'New Jersey': /^[A-Z]\d{14}$/,
	'New Mexico': /^\d{9}$/,
	'New York': /^\d{9}$|^[A-Z]\d{8}$/,
	'North Carolina': /^\d{12}$/,
	'North Dakota': /^\d{9}$/,
	Ohio: /^[A-Z]{2}\d{6,8}$/,
	Oklahoma: /^[A-Z]\d{9}$/,
	Oregon: /^[A-Z]\d{7}$/,
	Pennsylvania: /^\d{8}$/,
	'Rhode Island': /^\d{7}$/,
	'South Carolina': /^\d{9}$/,
	'South Dakota': /^\d{8}$/,
	Tennessee: /^\d{8,9}$/,
	Texas: /^\d{8}$/,
	Utah: /^\d{4,10}$|^[A-Z]\d{6,9}$/,
	Vermont: /^\d{8}$|^\d{7}[A-Z]$/,
	Virginia: /^[A-Z]\d{8}$/,
	Washington: /^[A-Z]\d{7}$/,
	'West Virginia': /^\d{7}$/,
	Wisconsin: /^[A-Z]\d{13}$/,
	Wyoming: /^\d{9}$/,
};
