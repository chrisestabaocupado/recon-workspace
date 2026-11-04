import type { IBuffer } from "@xterm/xterm";

/** Plain text from the whole retained buffer, without artificial line wraps. */
export function terminalOutput(buffer: Pick<IBuffer, "length" | "getLine">) {
	let text = "";
	for (let index = 0; index < buffer.length; index++) {
		const line = buffer.getLine(index);
		if (!line) continue;
		if (index > 0 && !line.isWrapped) text += "\n";
		text += line.translateToString(!buffer.getLine(index + 1)?.isWrapped);
	}
	return text.replace(/\n+$/, "");
}
