<div align="center">
    <h1 align="center">@chronark/access</h1>
    <h5>Simple Access Control</h5>
</div>

<br/>

A minimal library for access control. It is designed to be used together with
opaque access tokens by providing a simple interface to define roles with
different access permissions and verifying requests to resources.

- Fully typed
- Zero dependencies
- Serializable to store in a database

## Install

```
npm i @chronark/access
```

## Usage

```typescript
import { AccessControl, Role } from "@chronark/access";

/**
 * Define all your resources and their access patterns
 *
 * key => resource
 * value => array of access types
 */
type Statements = {
  "user": ["read", "write", "dance"];
  "team": ["read", "write"];
};

/**
 * Create an access control instance and pass the Statements type to enjoy full
 * type safety
 */
const ac = new AccessControl<Statements>();

/**
 * Now you can define one or more roles by specifying the access permissions
 *
 * This is already fully typed and typescript will let you know if you try to
 * use anything, that is not defined in the Statements type.
 */
const role = ac.newRole({
  user: ["read", "write"],
  team: ["read"],
});

/**
 * Simulate storing and retrieving the role in a database
 *
 * The idea here is, that you can store permissions alongside an API token.
 * Now, when you verify the token, you can also verify the access permissions.
 */
const serialized = role.toString();

/**
 * Note how you can pass in the Statements type again, to get full type safety
 */
const recovered = Role.fromString<Statements>(serialized);

/**
 * Validate the role by specifying the resource and the required access
 *
 * everything is fully typed
 */
const res = recovered.verify("team", ["read"]);

// res.success => boolean
// res.error => string | undefined provides a reason for failure
```
