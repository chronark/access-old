import type { Statements, SubArray, Subset } from "./types";

export class ParsingError extends Error {
  public readonly path: string;
  constructor(message: string, path: string) {
    super(message);
    this.path = path;
  }
}

export class AccessControl<TStatements extends Statements> {
  // public readonly statements: TStatements

  // constructor(statements: TStatements) {
  //     this.statements = statements
  // }

  public newRole<K extends keyof TStatements>(
    statements: Subset<K, TStatements>,
  ) {
    return new Role(statements);
  }
}

export type allowResponse =
  | { success: false; error: string }
  | { success: true; error?: never };

export class Role<TStatements extends Statements> {
  public readonly statements: TStatements;

  constructor(statements: TStatements) {
    this.statements = statements;
  }

  // public allow<TResource extends keyof TStatements>(req: { resource: TResource, actions: TStatements[TResource] }): allowResponse {
  public allow<TResource extends keyof TStatements>(
    resource: TResource,
    actions: SubArray<TStatements[TResource]>,
  ): allowResponse {
    for (const [r, as] of Object.entries(this.statements)) {
      if (resource === r) {
        for (const action of (actions)) {
          if (!as?.includes(action)) {
            return {
              success: false,
              error:
                `not authorized for action "${action}" on resource: "${r}"`,
            };
          }
        }
        return { success: true };
      }
    }

    return {
      success: false,
      error: `not authorized for resource "${resource.toString()}"`,
    };
  }

  static fromString<TStatements extends Statements = {}>(
    s: string,
  ): Role<TStatements> {
    const statements = JSON.parse(s) as TStatements;

    if (typeof statements !== "object") {
      throw new ParsingError("statements is not an object", ".");
    }
    for (const [resource, actions] of Object.entries(statements)) {
      if (typeof resource !== "string") {
        throw new ParsingError("invalid resource identifier", resource);
      }
      if (!Array.isArray(actions)) {
        throw new ParsingError("actions is not an array", resource);
      }
      for (let i = 0; i < actions.length; i++) {
        if (typeof actions[i] !== "string") {
          throw new ParsingError("action is not a string", `${resource}[${i}]`);
        }
      }
    }
    return new Role(statements);
  }

  public toString(): string {
    return JSON.stringify(this.statements);
  }
}
