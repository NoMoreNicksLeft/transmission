/* @license This file Copyright © Transmission authors and contributors.
   It may be used under the MIT (SPDX: MIT) license.
   License text can be found in the licenses/ folder. */

import { createDialogContainer } from './utils.js';

export class PublishDialog extends EventTarget {
  constructor(controller, remote, torrent) {
    super();

    this.controller = controller;
    this.remote = remote;
    this.torrent = torrent;

    this.elements = this._create();
    this.elements.dismiss.addEventListener('click', () => this.close());
    this.elements.confirm.addEventListener('click', () => this._onConfirm());
    document.body.append(this.elements.root);
    this.elements.key_input.focus();
  }

  close() {
    if (!this.closed) {
      this.elements.root.remove();
      this.dispatchEvent(new Event('close'));
      for (const key of Object.keys(this)) {
        delete this[key];
      }
      this.closed = true;
    }
  }

  _onConfirm() {
    const pem = this.elements.key_input.value.trim();
    if (!pem) {
      this.elements.status.textContent = 'Please enter the private key PEM.';
      return;
    }

    this.elements.confirm.disabled = true;
    this.elements.status.textContent = 'Publishing update\u2026';

    const args = {
      ids: [this.torrent.getId()],
      private_key: pem,
    };

    if (this.elements.continue_seeding.checked) {
      args.continue_seeding = true;
    }

    this.remote.sendRequest(
      {
        method: 'btpk_publish',
        arguments: args,
      },
      (response) => {
        if (response.result === 'success') {
          this.elements.status.textContent = 'Update published successfully.';
          setTimeout(() => this.close(), 1500);
        } else {
          this.elements.status.textContent = `Error: ${response.result}`;
          this.elements.confirm.disabled = false;
        }
      },
    );
  }

  _create() {
    const elements = createDialogContainer('publish-dialog');
    elements.heading.textContent = 'Publish Mutable Torrent Update';

    const workarea = elements.workarea;

    // Torrent name
    const name_div = document.createElement('div');
    name_div.classList.add('publish-torrent-name');
    name_div.textContent = this.torrent.getName();
    workarea.append(name_div);

    // Current sequence info
    const seq_div = document.createElement('div');
    seq_div.classList.add('publish-seq-info');
    seq_div.textContent = `Current sequence: ${this.torrent.getBtpkSeq()}`;
    workarea.append(seq_div);

    // Public key fingerprint
    const pub_div = document.createElement('div');
    pub_div.classList.add('publish-pub-info');
    const pub = this.torrent.getBtpkPub();
    pub_div.textContent = `Public key: ${pub.substring(0, 16)}\u2026`;
    workarea.append(pub_div);

    // PEM key input
    const key_label = document.createElement('label');
    key_label.textContent = 'Private Key (PEM):';
    key_label.htmlFor = 'publish-pem-input';
    workarea.append(key_label);

    const key_input = document.createElement('textarea');
    key_input.id = 'publish-pem-input';
    key_input.classList.add('publish-pem-field');
    key_input.rows = 5;
    key_input.placeholder = '-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----';
    workarea.append(key_input);
    elements.key_input = key_input;

    // Continue seeding checkbox
    const check_div = document.createElement('div');
    check_div.classList.add('publish-option');
    const check = document.createElement('input');
    check.type = 'checkbox';
    check.id = 'publish-continue-seeding';
    check.checked = true;
    check_div.append(check);
    const check_label = document.createElement('label');
    check_label.htmlFor = 'publish-continue-seeding';
    check_label.textContent = 'Continue seeding previous version';
    check_div.append(check_label);
    workarea.append(check_div);
    elements.continue_seeding = check;

    // Status message
    const status = document.createElement('div');
    status.classList.add('publish-status');
    workarea.append(status);
    elements.status = status;

    // Buttons
    elements.confirm.textContent = 'Publish';
    elements.dismiss.textContent = 'Cancel';

    return elements;
  }
}
