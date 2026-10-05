import { CheckboxField, SelectField, TextArea, TextField } from "@/components/fields";

/** Fields shared by scan-report and retest-report requests. */
export function ReportRequestFields({ defaultTitle }: { defaultTitle: string }) {
  return (
    <>
      <TextField name="title" label="Title" required defaultValue={defaultTitle} />
      <TextField name="reviewed_by" label="Reviewed by" />
      <SelectField
        name="kind"
        label="Kind"
        options={[
          ["draft", "Draft"],
          ["final", "Final (requires the assessment to be completed)"],
        ]}
        defaultValue="draft"
      />
      <SelectField
        name="classification"
        label="Classification"
        options={[
          ["confidential", "Confidential"],
          ["internal", "Internal"],
          ["restricted", "Restricted"],
        ]}
        defaultValue="confidential"
      />
      <fieldset>
        <legend>Formats</legend>
        <CheckboxField name="formats" value="json" defaultChecked required>
          JSON (always generated)
        </CheckboxField>
        <CheckboxField name="formats" value="html" defaultChecked>
          HTML
        </CheckboxField>
        <CheckboxField name="formats" value="pdf" defaultChecked>
          PDF
        </CheckboxField>
      </fieldset>
      <TextArea name="executive_summary_note" label="Executive summary note" maxLength={4000} />
      <TextArea name="scope_note" label="Scope note" maxLength={4000} />
    </>
  );
}
