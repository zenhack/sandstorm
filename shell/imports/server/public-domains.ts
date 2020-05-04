// Sandstorm - Personal Cloud Sandbox
// Copyright (c) 2020 Sandstorm Development Group, Inc. and contributors
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

import { SandstormDb } from "/imports/sandstorm-db/db.js";

import { SystemPersistent } from "/imports/server/capnp/supervisor.js";
import { PublicWebView } from "/imports/server/capnp/public-domains.js";
import { PublicWebViewSetter } from "/imports/server/capnp/public-domains-internal.js";

class PublicWebViewSetterImpl extends PublicWebViewSetter {
  db: SandstormDb
  domain: string
  grainId: string

  constructor(db: SandstormDb, domain: string, grainId: string) {
    super();
    this.db = db;
    this.domain = domain;
    this.grainId = grainId;
  }

  set(value: PublicWebView | null): Promise<void> {
    if(value === null) {
      this.db.clearPublicWebView(this.domain);
      return Promise.resolve();
    }
    return value.castAs(SystemPersistent).save({ frontend: null }).then((result) => {
      const sturdyRef: Buffer = result.sturdyRef;
      this.db.setPublicWebView(this.domain, this.grainId, sturdyRef);
    })
  }
}
