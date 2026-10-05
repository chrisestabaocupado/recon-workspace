import { useId } from "react";
import { Input } from "../ui/input";
import { Textarea } from "../ui/textarea";

export function PlanField({
	label,
	value,
	onChange,
	hint,
	multiline = false,
	type = "text",
	min,
	max,
	placeholder,
	disabled,
	autoComplete,
}: {
	label: string;
	value: string | number;
	onChange: (value: string) => void;
	hint?: string;
	multiline?: boolean;
	type?: string;
	min?: number;
	max?: number;
	placeholder?: string;
	disabled?: boolean;
	autoComplete?: string;
}) {
	const id = useId();
	const props = {
		id,
		value,
		onChange: (
			event: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement>,
		) => onChange(event.target.value),
		"aria-describedby": hint ? `${id}-hint` : undefined,
		placeholder,
		disabled,
		autoComplete,
	};
	return (
		<div className="grid gap-2">
			<label htmlFor={id} className="text-xs font-medium">
				{label}
			</label>
			{multiline ? (
				<Textarea {...props} rows={4} />
			) : (
				<Input
					{...props}
					type={type}
					min={min}
					max={max}
					onChange={type === "datetime-local" ? undefined : props.onChange}
					onInput={
						type === "datetime-local"
							? (event) => onChange(event.currentTarget.value)
							: undefined
					}
				/>
			)}
			{hint && (
				<p
					id={`${id}-hint`}
					className="m-0 text-xs leading-relaxed text-muted-foreground"
				>
					{hint}
				</p>
			)}
		</div>
	);
}
export function localDateInput(iso: string): string {
	if (!iso) return "";
	const date = new Date(iso);
	return new Date(date.getTime() - date.getTimezoneOffset() * 60000)
		.toISOString()
		.slice(0, 16);
}
export function isoDateInput(local: string): string {
	if (!local) return "";
	const date = new Date(local);
	return Number.isFinite(date.getTime()) ? date.toISOString() : "";
}
