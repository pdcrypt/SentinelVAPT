import type { ReactNode } from "react";

// Plain form fields (no state), usable inside <ActionForm>.

export function TextField({
  name,
  label,
  hint,
  required = false,
  defaultValue,
  placeholder,
  maxLength = 200,
}: {
  name: string;
  label: string;
  hint?: ReactNode;
  required?: boolean;
  defaultValue?: string;
  placeholder?: string;
  maxLength?: number;
}) {
  return (
    <div className="field">
      <label htmlFor={`f-${name}`}>
        {label}
        {required ? " *" : ""}
      </label>
      <input
        id={`f-${name}`}
        name={name}
        type="text"
        required={required}
        defaultValue={defaultValue}
        placeholder={placeholder}
        maxLength={maxLength}
        autoComplete="off"
        spellCheck={false}
      />
      {hint && <span className="hint">{hint}</span>}
    </div>
  );
}

export function TextArea({
  name,
  label,
  hint,
  required = false,
  defaultValue,
  maxLength = 5000,
}: {
  name: string;
  label: string;
  hint?: ReactNode;
  required?: boolean;
  defaultValue?: string;
  maxLength?: number;
}) {
  return (
    <div className="field">
      <label htmlFor={`f-${name}`}>
        {label}
        {required ? " *" : ""}
      </label>
      <textarea
        id={`f-${name}`}
        name={name}
        required={required}
        defaultValue={defaultValue}
        maxLength={maxLength}
        spellCheck={false}
      />
      {hint && <span className="hint">{hint}</span>}
    </div>
  );
}

export function DateTimeField({
  name,
  label,
  defaultValue,
}: {
  name: string;
  label: string;
  defaultValue: string;
}) {
  return (
    <div className="field">
      <label htmlFor={`f-${name}`}>{label} * (UTC)</label>
      <input
        id={`f-${name}`}
        name={name}
        type="datetime-local"
        required
        defaultValue={defaultValue}
      />
    </div>
  );
}

export function SelectField({
  name,
  label,
  options,
  defaultValue,
  hint,
}: {
  name: string;
  label: string;
  options: readonly (readonly [string, string])[];
  defaultValue?: string;
  hint?: ReactNode;
}) {
  return (
    <div className="field">
      <label htmlFor={`f-${name}`}>{label}</label>
      <select id={`f-${name}`} name={name} defaultValue={defaultValue}>
        {options.map(([value, text]) => (
          <option key={value} value={value}>
            {text}
          </option>
        ))}
      </select>
      {hint && <span className="hint">{hint}</span>}
    </div>
  );
}

export function CheckboxField({
  name,
  children,
  required = false,
  defaultChecked = false,
  value = "true",
}: {
  name: string;
  children: ReactNode;
  required?: boolean;
  defaultChecked?: boolean;
  value?: string;
}) {
  return (
    <label className="checkbox">
      <input
        type="checkbox"
        name={name}
        value={value}
        required={required}
        defaultChecked={defaultChecked}
      />
      <span>{children}</span>
    </label>
  );
}
