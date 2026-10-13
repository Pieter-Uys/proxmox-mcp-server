// ─── Tool argument validation ───────────────────────────────────────────────
// Checks arguments against a tool's inputSchema. Supports the JSON Schema
// subset the tools use: type, enum, pattern, minimum, required, and rejects
// properties the schema doesn't declare.

const TYPE_CHECKS = {
  string: (value) => typeof value === "string",
  number: (value) => typeof value === "number" && Number.isFinite(value),
  integer: (value) => Number.isInteger(value),
  boolean: (value) => typeof value === "boolean",
  object: (value) =>
    value !== null && typeof value === "object" && !Array.isArray(value),
};

function checkValue(name, value, schema) {
  if (schema.type && !TYPE_CHECKS[schema.type](value))
    return `${name} must be of type ${schema.type}`;
  if (schema.enum && !schema.enum.includes(value))
    return `${name} must be one of: ${schema.enum.join(", ")}`;
  if (schema.pattern && !new RegExp(schema.pattern).test(value))
    return `${name} has an invalid format (must match ${schema.pattern})`;
  if (schema.minimum !== undefined && value < schema.minimum)
    return `${name} must be at least ${schema.minimum}`;
  return null;
}

// Returns a list of problems; an empty list means the arguments are valid.
export function validateArgs(inputSchema, args) {
  if (!TYPE_CHECKS.object(args)) return ["arguments must be an object"];
  const { properties = {}, required = [] } = inputSchema;
  const problems = [];
  for (const name of required) {
    if (args[name] === undefined) problems.push(`${name} is required`);
  }
  for (const [name, value] of Object.entries(args)) {
    if (!Object.hasOwn(properties, name)) {
      problems.push(`${name} is not a recognised argument`);
      continue;
    }
    if (value === undefined) continue;
    const problem = checkValue(name, value, properties[name]);
    if (problem) problems.push(problem);
  }
  return problems;
}

// Checks a tool's requiredWhen rules, e.g. "pos is required when action is delete".
export function checkRequiredWhen(rules = [], args) {
  const problems = [];
  for (const { field, values, required } of rules) {
    if (!values.includes(args[field])) continue;
    for (const name of required) {
      if (args[name] === undefined) problems.push(`${name} is required when ${field} is ${args[field]}`);
    }
  }
  return problems;
}
