import { Injectable } from '@nestjs/common';
import axios from 'axios';

@Injectable()
export class HealthService {
	private readonly URL_UPTIME: string;

	constructor() {
		this.URL_UPTIME = process.env.URL_UPTIME;
	}

	async getTokenUptime() {
		let token = await axios.post(
			this.URL_UPTIME + '/login/access-token',
			{
				username: process.env.UPTIME_USERNAME,
				password: process.env.UPTIME_PASSWORD,
			},
			{
				headers: {
					'Content-Type': 'application/x-www-form-urlencoded',
					'accept': 'application/json',
				},
			},
		);
		if (token.status !== 200) {
			throw new Error('Error getting token');
		}
		token = token.data.access_token;
		return `Bearer ${token}`;
	}

	async getDataUptime(token: string) {
		let userInfo = await axios.get(
			this.URL_UPTIME + '/monitors',
			{
				headers: {
					Authorization: token,
				},
			},
		);
		if (userInfo.status !== 200) {
			throw new Error('Error getting data');
		}
		return userInfo.data ;
	}

	async getBeatUptime(id: number, hour:number,token: string) {
		let userInfo = await axios.get(
			this.URL_UPTIME + `/monitors/${id}/beats?hours=${hour}`,
			{
				headers: {
					Authorization: token,
				},
			},
		);
		if (userInfo.status !== 200) {
			throw new Error('Error getting data');
		}
		return userInfo.data.monitor_beats;
	}

}
