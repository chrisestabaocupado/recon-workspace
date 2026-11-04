export type TerminalSize = { cols: number; rows: number };
export type TerminalSession = { id: string; secret: string };
export type TerminalFrame = {
	data: string;
	offset: number;
	truncated: boolean;
	state: "connected" | "closed";
	message: string;
};
