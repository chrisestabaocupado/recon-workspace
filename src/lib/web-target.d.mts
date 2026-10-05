export type NiktoTarget = {
	host: string;
	port: number;
	tls: boolean;
	root: string;
	url: string;
};
export function parseNiktoTarget(q: {
	target: string;
	port: number;
	tls: boolean;
}): NiktoTarget;
