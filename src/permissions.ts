
import type { SubArray, Statements, Subset } from "./types";


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

export type VerifyResponse =
    | { success: false; error: string }
    | { success: true; error?: never };

export class Role<TStatements extends Statements> {
    public readonly statements: TStatements;

    constructor(statements: TStatements) {
        this.statements = statements;
    }

    // public verify<TResource extends keyof TStatements>(req: { resource: TResource, actions: TStatements[TResource] }): VerifyResponse {
    public verify<TResource extends keyof TStatements>(
        req: { resource: TResource; actions: SubArray<TStatements[TResource]> },
    ): VerifyResponse {
        console.log({ req, statements: this.statements });

        for (const [r, as] of Object.entries(this.statements)) {
            if (req.resource === r) {
                for (const action of (req.actions as unknown as string[])) {
                    if (!as?.includes(action)) {
                        return {
                            success: false,
                            error:
                                `not authorization for action "${action}" on resource: "${r}"`,
                        };
                    }
                }
                return { success: true };
            }
        }

        return {
            success: false,
            error: `not authorized for resource "${req.resource.toString()}"`,
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
