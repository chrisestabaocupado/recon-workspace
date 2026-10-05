import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";

const release = readFileSync("/etc/os-release", "utf8");
const distro = release.match(/^ID=(?:"([^"]+)"|([^\s]+))$/m);
const distroId = distro?.[1] ?? distro?.[2] ?? "";
const nmap =
	process.platform === "linux" && distroId === "kali"
		? spawnSync("nmap", ["--version"], {
				encoding: "utf8",
				timeout: 5000,
				maxBuffer: 16384,
			})
		: undefined;
console.log(
	JSON.stringify({
		platform: process.platform,
		distro: distroId,
		node: process.version,
		nmap: nmap?.status === 0 ? nmap.stdout.split("\n")[0] : "",
	}),
);
