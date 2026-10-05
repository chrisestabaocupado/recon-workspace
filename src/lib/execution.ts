import type { KaliExecutor } from "./kali.ts";
export type JobState =
	| "starting"
	| "running"
	| "cancelling"
	| "completed"
	| "failed"
	| "cancelled"
	| "timed_out"
	| "unknown"
	| "interrupted";
export const isActiveJob = (state: JobState) =>
	["starting", "running", "cancelling"].includes(state);
export type ExecutionSnapshot = {
	id: string;
	projectId: string;
	command: string;
	targets: string[];
	mode: "local" | "ssh";
	startedAt: string;
	scopeRevision?: number;
	executor?: KaliExecutor;
};
export type ExecutionView = ExecutionSnapshot & {
	state: JobState;
	logs: string;
	error?: string;
	truncated: boolean;
	artifactAvailable: boolean;
	finishedAt?: string;
};
export type RunnerEvent =
	| { type: "ready"; pid: number }
	| { type: "log"; stream: "stdout" | "stderr"; data: string }
	| { type: "error"; message: string }
	| { type: "warning"; message: string }
	| { type: "artifact"; data: string; filename: string }
	| {
			type: "exit";
			code: number | null;
			signal?: string;
			reason?: "cancelled" | "timed_out";
	  };
