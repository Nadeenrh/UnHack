// Runtime validation against contracts/*.schema.json (the same files the agent service uses).

import Ajv2020, { type ErrorObject } from "ajv/dist/2020";
import addFormats from "ajv-formats";
import incidentSchema from "@/contracts/incident.schema.json";
import investigationSchema from "@/contracts/investigation.schema.json";
import type { Incident, InvestigationResult } from "@/contracts/types";

const ajv = new Ajv2020({ allErrors: true, strict: false });
addFormats(ajv);
ajv.addSchema(investigationSchema);

const incidentValidator = ajv.compile(incidentSchema);
const resultValidator = ajv.getSchema(`${investigationSchema.$id}#/$defs/result`)!;
const requestValidator = ajv.getSchema(`${investigationSchema.$id}#/$defs/request`)!;

function describe(errors: ErrorObject[] | null | undefined): string {
  return (errors ?? []).map((e) => `${e.instancePath || "(root)"} ${e.message}`).join("; ");
}

export function validateIncident(value: unknown): { ok: true; value: Incident } | { ok: false; error: string } {
  return incidentValidator(value) ? { ok: true, value: value as unknown as Incident } : { ok: false, error: describe(incidentValidator.errors) };
}

export function validateInvestigationResult(
  value: unknown
): { ok: true; value: InvestigationResult } | { ok: false; error: string } {
  return resultValidator(value)
    ? { ok: true, value: value as unknown as InvestigationResult }
    : { ok: false, error: describe(resultValidator.errors) };
}

export function validateInvestigationRequest(value: unknown): { ok: true } | { ok: false; error: string } {
  return requestValidator(value) ? { ok: true } : { ok: false, error: describe(requestValidator.errors) };
}
