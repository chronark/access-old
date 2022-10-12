import { AccessControl, Role } from "./index"


/**
 * Define all your possible access controls
 *
 * key => resource
 * value => array of access types
 */
type MyStatements = {
    "user": ["read", "write", "dance"];
    "team": ["read", "write"];
};

/**
 * Create an access control instance
 */
const ac = new AccessControl<MyStatements>();

/**
 * Define one or more roles
 */
const role = ac.newRole({
    team: ["read"],
    user: ["read", "write"],
});

/**
 * Simulate storing and retrieving this in a database
 */
const serialized = role.toString();
const recovered = Role.fromString<MyStatements>(serialized);

/**
 * Validate the role by specifying the resource and the required access
 * 
 * everything is fully typed
 */
const { success, error } = recovered.verify({
    resource: "team",
    actions: ["read"],
});

console.log({ success, error });
