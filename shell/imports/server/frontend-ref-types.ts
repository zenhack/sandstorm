// Types used by frontend-ref.js's API. TODO: once we convert that file over to
// typescript, these definitions should be moved into it.

import { SandstormDb } from "/imports/sandstorm-db/db.js";

// Defined in capnproto file; ideally we'd generate typescript declarations
// from those:
type MembraneRequirement = any;

// TODO: get rid of uses of `any`.

export interface FrontendRefCallback<T> {
  // Register callbacks related to a particular frontendRef type.

  frontendRefField: string;
  // Name of the field of `ApiTokens.frontendRef` that is filled in for
  // this type. Only needed if `create` and/or `validate` handlers are defined.

  typeId: string;
  // Type ID of powerbox tags handled by the `query` callback. Stringified decimal
  // 64-bit integer. Only needed if `query` is defined.

  restore(db: SandstormDb, saveTemplate: any, value: T): any;
  // Callback to construct a capability of this type when restoring a saved
  // capability. Has signature `(db, saveTemplate, value) -> capability`, where:
  //     `value`: The value of the single field of `ApiTokens.frontendRef` for this capability.
  //     `saveTemplate`: The token template to pass to the PersistentImpl constructor.
  //     `capability` (returned): A Cap'n Proto capability implementing SystemPersistent along
  //         with whatever other interfaces are appropriate for the ref type.

  validate(db: SandstormDb, session: any, request: object): ValidateResults<T>;
  // Callback to validate a powerbox request for a new capability of this type.
  //     `request` is type-specific information describing the requested capability. The
  //         callback *must* type-check this value, and should throw an exception if it is
  //         not valid.
  //     `session` is the record from the Sessions table of the UI session where the powerbox
  //         request occurred.

  query(db: SandstormDb, userAccountId: string, tagValue: Buffer): Array<object>
  // Callback to populate options for a powerbox request for this type ID. Has
  //        signature `(db, userAccountId, tagValue) -> options`, where:
  //      `tagValue`: A Buffer of the Cap'n-Proto-encoded `PowerboxDescriptor.Tag.value`.
  //      `options` (returned): An array of objects representing the options that should be
  //          offered to the user for this query. See the `powerboxOptions` Meteor publish in
  //          powerbox-server.js for a full description of the fields of each option.
}

export interface ValidateResults<T> {
  // Return value from FrontendRefCallback.validate()

  descriptor: object;
  // the JSON-encoded PowerboxDescriptor for the capability. Note
  // that if the descriptor contains any `tag.value`s, they of course need to be
  // presented as capnp-encoded Buffers.
  requirements: Array<MembraneRequirement>;
  //     `requirements` (returned) is an array of MembraneRequirements which should apply to the
  //         new capability. Note that these requirements will be checked immediately and the
  //         powerbox request will fail if they aren't met.
  frontendRef: T;
  //     `frontendRef` (returned) is the value that will be written for the key specified
  //         by `frontendRefField` in the single-key object `ApiTokens.frontendRef`.
}
