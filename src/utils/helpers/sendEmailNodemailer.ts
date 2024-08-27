import { createTransport } from 'nodemailer';
import * as Sentry from "@sentry/nestjs";

export const sendEmailNodemailer = async (to, subject, text, html) => {
	const transporter = createTransport({
		host: 'smtp.gmail.com',
		port: 465,
		secure: true,
		auth: {
			user: process.env.EMAIL_USER ?? '',
			pass: process.env.EMAIL_PASS ?? '',
		},
	});

	const mailOptions = {
		from: process.env.EMAIL_USER ?? '',
		to,
		subject,
		text,
		html,
	};

	try {
		const info = await transporter.sendMail(mailOptions);
		console.log('Email enviado:', info.response);
	} catch (error) {
		Sentry.captureException(error);
		console.error('Error al enviar el correo:', error);
	}
};
