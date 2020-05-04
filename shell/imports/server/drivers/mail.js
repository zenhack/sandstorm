// Sandstorm - Personal Cloud Sandbox
// Copyright (c) 2014 Sandstorm Development Group, Inc. and contributors
// All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

import { Meteor } from "meteor/meteor";
import { Match, check } from "meteor/check";
import { _ } from "meteor/underscore";
import { Random } from "meteor/random";
import { Accounts } from "meteor/accounts-base";

import { SMTPServer } from "smtp-server";
import { MailParser } from "mailparser";

import { SandstormDb } from "/imports/sandstorm-db/db.js";
import { globalDb } from "/imports/db-deprecated.js";
import { globalBackend } from "/imports/server/core.js";
import { PersistentImpl } from "/imports/server/persistent.js";
import { rawSend } from "/imports/server/email.js";
import { shouldRestartGrain } from "/imports/server/backend.js";
import { inMeteor } from "/imports/server/async-helpers.js";
import { makeHackSessionContext } from "/imports/server/hack-session.js";

import Crypto from "crypto";
import Future from "fibers/future";
import Net from "net";
import Url from "url";
import Capnp from "/imports/server/capnp.js";

const EmailRpc = Capnp.importSystem("sandstorm/email.capnp");
const EmailImpl = Capnp.importSystem("sandstorm/email-impl.capnp");
const HackSessionContext = Capnp.importSystem("sandstorm/hack-session.capnp").HackSessionContext;
const Supervisor = Capnp.importSystem("sandstorm/supervisor.capnp").Supervisor;
const EmailSendPort = EmailRpc.EmailSendPort;

const ROOT_URL = Url.parse(process.env.ROOT_URL);
const HOSTNAME = ROOT_URL.hostname;

const RECIPIENT_LIMIT = 20;

const CLIENT_TIMEOUT = 15000; // 15s

// Every day, reset all per-user sent counts to zero.
// TODO(cleanup): Consider a more granular approach. For example, each user could have a timer
//   after which their count will reset. We'd only check the timer when that user is trying to
//   send a new message. This avoids a global query.
if (!Meteor.settings.replicaNumber) {  // only first replica
  SandstormDb.periodicCleanup(86400000, () => {
    Meteor.users.update({ dailySentMailCount: { $exists: true } },
                        { $unset: { dailySentMailCount: "" } },
                        { multi: true });
  });
}

if (process.env.HTTP_GATEWAY === "local" &&
    !global.sandstormListenCapabilityStream) {
  // TODO(cleanup): This is supposed to come from meteor-bundle-main.js but that doesn't actually
  //   run in dev-mode servers.
  const { Pipe, constants: PipeConstants } = process.binding('pipe_wrap');

  global.sandstormListenCapabilityStream = function (fd, cb) {
    var pipe = new Pipe(PipeConstants.IPC);
    pipe.open(fd);
    pipe.onread = function (size, buf, handle) {
      if (handle) {
        cb(new Net.Socket({ handle: handle }));
      }
    };
    pipe.readStart();
  }
}

Meteor.startup(function () {
  const server = new SMTPServer({
    banner: "Sandstorm Mail Server",
    authOptional: true,
    disabledCommands: ["STARTTLS", "AUTH"],
    onData: (req, session, callback) => {
      const mailparser = new MailParser();
      req.pipe(mailparser);

      mailparser.on("end", (mail) => {
        // Wrap in outer promise for easier error handling.
        Promise.resolve().then(() => {
          // Extract the 'from' address.
          let from;
          if (mail.from && mail.from.length > 0) {
            // It's theoretically possible for the message to have multiple 'from' headers, but this
            // never really happens in legitimate practice so we'll just take the first one.
            from = mail.from[0];
          } else {
            // The mail body is missing a 'From:' header. We'll use the bounce address instead,
            // with the caveat that this is sometimes *not* the original sender
            // but rather some intermediate agent (e.g. a mailing list daemon). See:
            //   http://en.wikipedia.org/wiki/Bounce_address
            // TODO(someday): Is this really right, or should we report a blank address instead?
            from = { address: session.envelope.mailFrom, name: false };
          }

          let attachments = [];
          if (mail.attachments) {
            attachments = mail.attachments.map((attachment) => {
              let disposition = attachment.contentDisposition || "attachment";
              disposition += ';\n\tfilename="' + (attachment.fileName || attachment.generatedFileName) + '"';
              return {
                contentType: attachment.contentType,
                contentDisposition: disposition,
                contentId: attachment.contentId,
                content: attachment.content,
              };
            });
          }

          if (mail.replyTo && mail.replyTo.length > 1) {
            console.error("More than one reply-to address address was received in an email.");
          }

          const mailMessage = {
            // Note that converting the date to nanoseconds actually goes outside the range of
            // integers that Javascript can represent precisely. But this is OK because dates aren't
            // precise anyway.
            date: (mail.date || new Date()).getTime() * 1000000,
            from: from,
            to: mail.to,
            cc: mail.cc || [],
            bcc: mail.bcc || [],
            replyTo: (mail.replyTo && mail.replyTo[0]) || {},
            messageId: mail.headers["message-id"] || Random.id() + "@" + HOSTNAME,
            references: mail.references || [],
            inReplyTo: mail.inReplyTo || [],
            subject: mail.subject || "",
            text: mail.text || null,
            html: mail.html || null,
            attachments: attachments,
          };

          // Get list of grain IDs.
          const grainPublicIds = _.uniq(session.envelope.rcptTo.map((deliverTo) => {
            // smtp-server already validates that the address contains an @.
            // To simplify things, we ignore the hostname part of the address and assume that the
            // message would not have been sent here if it weren't intended for our host. Usually
            // there will be an nginx frontend verifying hostnames anyway. Grain public IDs are
            // globally unique anyway, so an e-mail meant for another server presumably won't match
            // any ID at this one anyway.
            const { address } = deliverTo;
            return address.slice(0, address.indexOf("@"));
          }));

          // Deliver to each grain in parallel.
          return Promise.all(grainPublicIds.map((publicId) => {
            // Wrap in a function so that we can call it recursively to retry.
            const tryDeliver = (retryCount) => {
              let grainId;
              return inMeteor(() => {
                const grain = globalDb.collections.grains.findOne({ publicId: publicId }, { fields: {} });
                if (grain) {
                  grainId = grain._id;
                  return globalBackend.continueGrain(grainId, retryCount > 0);
                } else {
                  // TODO(someday): We really ought to rig things up so that the 'RCPT TO' SMTP command
                  // fails in this case, by adding an onRcptTo() callback.
                  throw new Error("No such grain: " + publicId);
                }
              }).then((grainInfo) => {
                const supervisor = grainInfo.supervisor;
                const uiView = supervisor.getMainView().view;

                // Create an arbitrary struct to use as the session params. E-mail sessions actually
                // require no params, but node-capnp won't let us pass null and we don't have an
                // EmptyStruct type available, so we just use EmailAddress, but any struct type would
                // work.
                // TODO(cleanup): Fix node-capnp to accept null.
                const emptyParams = Capnp.serialize(EmailRpc.EmailAddress, {});

                // Create a new session of type HackEmailSession. This is a short-term hack until
                // persistent capabilities and the Powerbox are implemented. We need to pass along a
                // HackSessionContext because old versions of sandstorm-http-bridge always use
                // the context of the most recent session; if an old RoundCube grain has a
                // WebSession open, receives an email, and then tries to send an email, the request
                // will go out on the SessionContext associated with the HackEmailSession that
                // delivered the email.
                const session = uiView
                    .newSession({}, makeHackSessionContext(grainId),
                                "0xc3b5ced7344b04a6", emptyParams)
                    .session.castAs(EmailSendPort);
                return session.send(mailMessage);
              }).catch((err) => {
                if (shouldRestartGrain(err, retryCount)) {
                  return tryDeliver(retryCount + 1);
                } else {
                  throw err;
                }
              });
            };

            return tryDeliver(0);
          }));
        }).then(() => {
          callback(null, "Message delivered");
        }, (err) => {
          console.error("E-mail delivery failure:", err.stack);
          const mailErr = new Error(err.message);
          err.responseCode = 451;
          callback(err.message);
        });
      });
    },
  });

  if (process.env.HTTP_GATEWAY === "local") {
    // Gateway running locally, connecting over unix socketpair via SCM_RIGHTS transfer.
    global.sandstormListenCapabilityStream(
        parseInt(process.env.SANDSTORM_SMTP_LISTEN_HANDLE), socket => {
      server.connect(socket);
    });
  } else {
    server.listen({ fd: parseInt(process.env.SANDSTORM_SMTP_LISTEN_HANDLE) });
  }
});

hackSendEmail = (session, email) => {
  return inMeteor((function () {
    let recipientCount = 0;
    recipientCount += email.to ? email.to.length : 0;
    recipientCount += email.cc ? email.cc.length : 0;
    recipientCount += email.bcc ? email.bcc.length : 0;
    if (recipientCount > RECIPIENT_LIMIT) {
      throw new Error(
          "Sorry, Sandstorm currently only allows you to send an e-mail to " + RECIPIENT_LIMIT +
          " recipients at a time, for spam control. Consider setting up a mailing list. " +
          "Please feel free to contact us if this is a problem for you.");
    }

    const grainAddress = session._getAddress();
    const userAddress = session._getUserAddress();

    // Overwrite the 'from' address with the grain's address.
    if (!email.from) {
      email.from = {
        address: grainAddress,
      };
    }

    if (email.from.address !== grainAddress && email.from.address !== userAddress.address) {
      throw new Error(
        "FROM header in outgoing emails need to equal either " + grainAddress + " or " +
        userAddress.address + ". Yours was: " + email.from.address);
    }

    // Unpack fields
    const { from, to, cc, bcc, replyTo, subject, text, html } = email;

    const options = {
      from,
      to,
      cc,
      bcc,
      replyTo,
      subject,
      text,
      html,
      envelope: {
        from: grainAddress,
        to,
        cc,
        bcc,
      },
    };

    const headers = {};
    if (email.messageId) {
      headers["message-id"] = email.messageId;
    }

    if (email.references) {
      headers["references"] = email.references; // jscs:ignore requireDotNotation
    }

    if (email.inReplyTo) {
      headers["in-reply-to"] = email.inReplyTo;
    }

    if (email.date) {
      const date = new Date(email.date / 1000000);
      if (!isNaN(date.getTime())) { // Check to make sure date is valid
        headers["date"] = date.toUTCString(); // jscs:ignore requireDotNotation
      }
    }

    options.headers = headers;

    if (email.attachments) {
      const attachments = [];
      email.attachments.forEach((attachment) => {
        attachments.push({
          filename: false, // Tell nodemailer not to generate a new filename.
          cid: attachment.contentId,
          contentType: attachment.contentType,
          contentDisposition: attachment.contentDisposition,
          content: attachment.content,
        });
      });
      options.attachments = attachments;
    }

    const grain = globalDb.collections.grains.findOne(session.grainId);
    if (!grain) throw new Error("Grain does not exist.");
    globalDb.incrementDailySentMailCount(grain.userId);

    rawSend(options);
  }).bind(this)).catch((err) => {
    console.error("Error sending e-mail:", err.stack);
    throw err;
  });
};

class EmailVerifierImpl extends PersistentImpl {
  constructor(db, saveTemplate, params) {
    super(db, saveTemplate);
    this._id = params.id;
    this._services = params.services;
  }

  getId() {
    return { id: new Buffer(this._id, "base64") };
  }

  verifyEmail(tabId, verification) {
    return unwrapFrontendCap(verification, "verifiedEmail", (verification) => {
      if (verification.tabId !== tabId.toString("hex")) {
        throw new Error("VerifiedEmail is from a different tab");
      }

      if (this._services) {
        // Since this verifier is restricted to specific services, only indicate a match if the
        // VerifiedEmail was for the correct verifier ID. (If our _services is null, then we
        // match all services, and therefore all VerifiedEmails.)
        if (verification.verifierId !== this._id) {
          throw new Error("VerifierEmail is for a different EmailVerifier.");
        }
      }

      return verification.address;
    });
  }
}

class VerifiedEmailImpl extends PersistentImpl {
  constructor(db, saveTemplate) {
    super(db, saveTemplate);
  }
}

function getVerifiedEmails(db, userId, verifierId) {
  // Get all of the email addresses verified as belonging to the given user using the given
  // verifier.

  let services = null;
  let couldAddAnother = true;

  if (verifierId) {
    const verifier = db.collections.apiTokens.findOne(
        { "frontendRef.emailVerifier.id": verifierId });
    if (!verifier) return []; // invalid verifier
    const verifierInfo = verifier.frontendRef.emailVerifier;

    if (verifierInfo.services) {
      // Limit to the listed services.
      services = {};
      verifierInfo.services.forEach(service => services[service] = true);
      couldAddAnother = !!services.email;
    }
  }

  const user = Meteor.users.findOne(userId);
  const emails = {};  // map address -> true, for uniquification

  Meteor.users.find({ _id: { $in: SandstormDb.getUserCredentialIds(user) } }).forEach(credential => {
    if (!services || services[SandstormDb.getServiceName(credential)]) {
      SandstormDb.getVerifiedEmailsForCredential(credential)
          .forEach(email => { emails[email.email] = true; });
    }
  });

  return { emails: Object.keys(emails), couldAddAnother };
}

// TODO(cleanup): Meteor.startup() needed because 00-startup.js runs *after* code in subdirectories
//   (ugh).
Meteor.startup(() => {
  globalFrontendRefRegistry.register({
    frontendRefField: "emailVerifier",
    typeId: EmailRpc.EmailVerifier.typeId,

    restore(db, saveTemplate, params) {
      return new Capnp.Capability(new EmailVerifierImpl(db, saveTemplate, params),
                                  EmailImpl.PersistentEmailVerifier);
    },

    validate(db, session, value) {
      check(value, { services: Match.Optional([String]) });

      const services = value.services;
      if (services) {
        services.forEach(service => {
          if (!Accounts.loginServices[service]) {
            throw new Error("No such login service: " + service);
          }
        });
      }

      value.id = Crypto.randomBytes(16).toString("base64");

      return {
        descriptor: { tags: [{ id: EmailRpc.EmailVerifier.typeId }] },
        requirements: [],
        frontendRef: value,
      };
    },

    query(db, userId, value) {
      const results = [];

      results.push({
        _id: "emailverifier-all",
        frontendRef: { emailVerifier: {} },
        cardTemplate: "emailVerifierPowerboxCard",
      });

      for (const name in Accounts.loginServices) {
        if (Accounts.loginServices[name].isEnabled()) {
          results.push({
            _id: "emailverifier-" + name,
            frontendRef: { emailVerifier: { services: [name] } },
            cardTemplate: "emailVerifierPowerboxCard",
          });
        }
      }

      return results;
    },
  });

  globalFrontendRefRegistry.register({
    frontendRefField: "verifiedEmail",
    typeId: EmailRpc.VerifiedEmail.typeId,

    restore(db, saveTemplate) {
      return new Capnp.Capability(new VerifiedEmailImpl(db, saveTemplate),
                                  EmailImpl.PersistentVerifiedEmail);
    },

    validate(db, session, value) {
      check(value, { verifierId: Match.Optional(String), address: String });

      if (!session.userId) {
        throw new Meteor.Error(403, "Not logged in.");
      }

      // Verify that the address actually belongs to the user.

      if (!_.contains(getVerifiedEmails(db, session.userId, value.verifierId).emails,
                      value.address)) {
        throw new Meteor.Error(403, "User has no such verified address");
      }

      // Add the session's tabId.
      value.tabId = session.tabId;

      // Build the descriptor, which contains the verifier ID.
      const tagValue = value.verifierId &&
          Capnp.serialize(EmailRpc.VerifiedEmail.PowerboxTag,
              { verifierId: new Buffer(value.verifierId, "hex") });

      return {
        descriptor: { tags: [{ id: EmailRpc.VerifiedEmail.typeId, value: tagValue }] },
        requirements: [],
        frontendRef: value,
      };
    },

    query(db, userId, value) {
      const verifierId = value &&
           Capnp.parse(EmailRpc.VerifiedEmail.PowerboxTag, value).verifierId.toString("base64");
      const verified = getVerifiedEmails(db, userId, verifierId);
      const result = verified.emails.map(address => ({
        _id: "email-" + address,
        frontendRef: { verifiedEmail: { verifierId, address } },
        cardTemplate: "verifiedEmailPowerboxCard",
        searchTerms: [address],
      }));

      if (verified.couldAddAnother) {
        result.push({
          _id: "email-add-a-new-one",
          frontendRef: { verifiedEmail: { verifierId }, },
          cardTemplate: "addNewVerifiedEmailPowerboxCard",
          configureTemplate: "addNewVerifiedEmailPowerboxConfiguration",
        });
      }

      return result;
    },
  });
});
