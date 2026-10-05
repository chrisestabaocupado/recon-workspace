import {
	autocompletion,
	type CompletionContext,
} from "@codemirror/autocomplete";
import { history, historyKeymap } from "@codemirror/commands";
import { EditorState } from "@codemirror/state";
import {
	EditorView,
	highlightActiveLine,
	keymap,
	lineNumbers,
} from "@codemirror/view";
import { useEffect, useRef } from "react";
import { nmapOptions } from "#/lib/nmap";

const editorTheme = EditorView.theme({
	"&": {
		height: "100%",
		backgroundColor: "transparent",
		color: "var(--foreground)",
		fontSize: "13px",
	},
	".cm-scroller": {
		fontFamily: "var(--font-mono, ui-monospace, SFMono-Regular, monospace)",
		overflow: "auto",
	},
	".cm-content": { padding: "16px 0" },
	".cm-gutters": {
		backgroundColor: "transparent",
		border: "none",
		color: "var(--muted-foreground)",
	},
	".cm-activeLineGutter": { backgroundColor: "transparent" },
	".cm-activeLine": {
		backgroundColor: "color-mix(in oklch, var(--primary) 5%, transparent)",
	},
	"&.cm-focused": { outline: "none" },
	".cm-cursor": { borderLeftColor: "var(--foreground)" },
	"&.cm-focused .cm-selectionBackground, .cm-selectionBackground, .cm-content ::selection":
		{
			backgroundColor:
				"color-mix(in oklch, var(--foreground) 20%, transparent)",
		},
	".cm-tooltip": {
		backgroundColor: "var(--popover)",
		color: "var(--popover-foreground)",
		border: "1px solid var(--border)",
	},
	".cm-tooltip-autocomplete": { borderRadius: "10px", overflow: "hidden" },
	".cm-tooltip-autocomplete ul li[aria-selected=true]": {
		backgroundColor: "var(--primary)",
		color: "var(--primary-foreground)",
	},
});

function completions(context: CompletionContext, targetSuggestions: string[]) {
	const word = context.matchBefore(/[\w-]*/);
	if (!word || (word.from === word.to && !context.explicit)) return null;
	const before = context.state.sliceDoc(0, word.from).trimEnd();
	const previousToken = before.split(/\s+/).at(-1) ?? "";
	const expectingValue = nmapOptions.find(
		(option) =>
			option.value &&
			option.flags.some(
				(flag) =>
					previousToken === flag ||
					(flag.startsWith("-") &&
						!flag.startsWith("--") &&
						previousToken.startsWith(flag) &&
						previousToken.length > flag.length),
			),
	);
	const valuePresets: Record<string, string[]> = {
		timing: ["0", "1", "2", "3", "4", "5"],
		"version-intensity": ["0", "1", "2", "3", "4", "5", "6", "7", "8", "9"],
		"top-ports": ["20", "100", "1000"],
		ports: ["22,80,443", "1-1024", "1-65535", "U:53,161,T:22,80,443"],
		scripts: ["default", "safe", "discovery", "vuln", "auth"],
	};
	const values = expectingValue
		? (valuePresets[expectingValue.id] ??
			(expectingValue.valueHint ? [expectingValue.valueHint] : []))
		: targetSuggestions;
	if (expectingValue)
		return {
			from: word.from,
			options: values.map((label) => ({
				label,
				detail: `${expectingValue.label} · ${expectingValue.group}`,
				type: "constant",
			})),
		};
	const options = nmapOptions.flatMap((option) =>
		option.flags.map((flag) => ({
			label: flag,
			detail: `${option.label} · ${option.group}`,
			type: option.value ? "function" : "keyword",
		})),
	);
	options.push(
		...values.map((label) => ({
			label,
			detail: "Objetivo guardado en este proyecto",
			type: "variable",
		})),
	);
	return { from: word.from, options };
}

export function NmapCommandEditor({
	value,
	onChange,
	targetSuggestions = [],
}: {
	value: string;
	onChange: (value: string) => void;
	targetSuggestions?: string[];
}) {
	const mountRef = useRef<HTMLDivElement>(null);
	const viewRef = useRef<EditorView | null>(null);
	const changeRef = useRef(onChange);
	const targetsRef = useRef(targetSuggestions);
	const initialValueRef = useRef(value);
	changeRef.current = onChange;
	targetsRef.current = targetSuggestions;

	useEffect(() => {
		if (!mountRef.current) return;
		const state = EditorState.create({
			doc: initialValueRef.current,
			extensions: [
				lineNumbers(),
				history(),
				keymap.of(historyKeymap),
				highlightActiveLine(),
				EditorView.lineWrapping,
				autocompletion({
					override: [(context) => completions(context, targetsRef.current)],
					activateOnTyping: true,
				}),
				editorTheme,
				EditorView.updateListener.of((update) => {
					if (update.docChanged) changeRef.current(update.state.doc.toString());
				}),
			],
		});
		const view = new EditorView({ state, parent: mountRef.current });
		viewRef.current = view;
		return () => {
			view.destroy();
			viewRef.current = null;
		};
	}, []);

	useEffect(() => {
		const view = viewRef.current;
		if (!view || view.state.doc.toString() === value) return;
		view.dispatch({
			changes: { from: 0, to: view.state.doc.length, insert: value },
		});
	}, [value]);

	return <div ref={mountRef} className="h-full min-h-[140px] text-left" />;
}
