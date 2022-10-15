import type { Statements, SubArray, Subset } from "./types";

export class ParsingError extends Error {
  public readonly path: string;
  constructor(message: string, path: string) {
    super(message);
    this.path = path;
  }
}

export class AccessControl<TStatements extends Statements = Statements> {
  public newRole<K extends keyof TStatements>(
    statements: Subset<K, TStatements>,
  ) {
    return new Role(statements);
  }
}

export type AuthortizeResponse =
  | { success: false; error: string }
  | { success: true; error?: never };

export class Role<TStatements extends Statements> {
  public readonly statements: TStatements;

  constructor(statements: TStatements) {
    this.statements = statements;
  }

  public authorize(
    request: TStatements,
  ): AuthortizeResponse {
    for (
      const [requestedResource, requestedActions] of Object.entries(request)
    ) {
      console.log(
        JSON.stringify(
          { requestedResource, requestedActions, statements: this.statements },
          null,
          2,
        ),
      );
      const allowedActions = this.statements[requestedResource];
      if (!allowedActions) {
        return {
          success: false,
          error: `You are not allowed to access resource: ${requestedResource}`,
        };
      }
      console.log(JSON.stringify({ allowedActions }, null, 2));
      const success = requestedActions.every((requestedAction) => {
        console.log(JSON.stringify({ requestedAction }, null, 2));
        for (const allowedAction of allowedActions) {
          // if (allowedAction.rid && allowedAction.rid !== requestedAction.rid){
          //   return false
          // }
          return allowedAction.action === requestedAction.action;
        }
        return false;
      });
      console.log({ success });
      if (success) {
        return { success };
      }
      return {
        success: false,
        error: `unauthorized to access resource "${requestedResource}"`,
      };
    }
    return {
      success: false,
      error: `Not authorized`,
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
