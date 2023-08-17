'use strict';
const express = require('express'),
  router = express.Router(),
  request = require('request'),
  crypto = require('crypto');


/**
* @typedef {Object} CreateMessage
* @property {string} @context - The context of the message.
* @property {string} id - The ID of the message.
* @property {string} type - The type of the message.
* @property {string} actor - The actor of the message.
* @property {string[]} to - The recipients of the message.
* @property {string[]} cc - The carbon copy recipients of the message.
* @property {Object} object - The object of the message.
*/

router.post('/sendMessage', function (req, res) {
  let db = req.app.get('db');
  let domain = req.app.get('domain');
  let acct = req.body.acct;
  let apikey = req.body.apikey;
  let message = req.body.message;
  // check to see if your API key matches
  let result = db.prepare('select apikey from accounts where name = ?').get(`${acct}@${domain}`);
  if (result.apikey === apikey) {
    sendCreateMessage(message, acct, domain, req, res);
  }
  else {
    res.status(403).json({ msg: 'wrong api key' });
  }
});

/**
 * Signs and sends a message to a target domain's inbox.
 *
 * @param {CreateMessage} message - The message to be sent.
 * @param {string} name - The name of the sender.
 * @param {string} domain - The domain of the sender.
 * @param {Express.request} req - The request object.
 * @param {Express.response} res - The response object.
 * @param {string} targetDomain - The domain of the target inbox.
 * @param {string} inbox - The URL of the target inbox.
 * @return {void}
 */
function signAndSend(message, name, domain, req, res, targetDomain, inbox) {
  // get the private key
  let db = req.app.get('db');
  let inboxFragment = inbox.replace('https://' + targetDomain, '');
  let result = db.prepare('select privkey from accounts where name = ?').get(`${name}@${domain}`);
  if (result === undefined) {
    console.log(`No record found for ${name}.`);
  }
  else {
    let privkey = result.privkey;
    const digestHash = crypto.createHash('sha256').update(JSON.stringify(message)).digest('base64');
    const signer = crypto.createSign('sha256');
    let d = new Date();
    let stringToSign = `(request-target): post ${inboxFragment}\nhost: ${targetDomain}\ndate: ${d.toUTCString()}\ndigest: SHA-256=${digestHash}`;
    signer.update(stringToSign);
    signer.end();
    const signature = signer.sign(privkey);
    const signature_b64 = signature.toString('base64');
    let header = `keyId="https://${domain}/u/${name}",headers="(request-target) host date digest",signature="${signature_b64}"`;
    request({
      url: inbox,
      headers: {
        'Host': targetDomain,
        'Date': d.toUTCString(),
        'Digest': `SHA-256=${digestHash}`,
        'Signature': header
      },
      method: 'POST',
      json: true,
      body: message
    }, function (error, response) {
      console.log(`Sent message to an inbox at ${targetDomain}!`);
      if (error) {
        console.log('Error:', error, response);
      }
      else {
        console.log('Response Status Code:', response.statusCode);
      }
    });
  }
}

/**
 * Creates a message with the given text and stores it in the database.
 *
 * @param {string} text - The content of the message.
 * @param {string} name - The name of the user creating the message.
 * @param {string} domain - The domain of the website where the message is being created.
 * @param {Express.request} req - The request object.
 * @param {Express.respone} res - The response object.
 * @param {string} follower - The follower of the user creating the message.
 * @return {CreateMessage} The created message object.
 */
function createMessage(text, name, domain, req, res, follower) {
  const guidCreate = crypto.randomBytes(16).toString('hex');
  const guidNote = crypto.randomBytes(16).toString('hex');
  let db = req.app.get('db');
  let d = new Date();

  let noteMessage = {
    'id': `https://${domain}/m/${guidNote}`,
    'type': 'Note',
    'published': d.toISOString(),
    'attributedTo': `https://${domain}/u/${name}`,
    'content': text,
    'to': ['https://www.w3.org/ns/activitystreams#Public'],
  };



  /**
   * @type {CreateMessage}
   */
  let createMessage = {
    '@context': 'https://www.w3.org/ns/activitystreams',

    'id': `https://${domain}/m/${guidCreate}`,
    'type': 'Create',
    'actor': `https://${domain}/u/${name}`,
    'to': ['https://www.w3.org/ns/activitystreams#Public'],
    'cc': [follower],

    'object': noteMessage
  };

  db.prepare('insert or replace into messages(guid, message) values(?, ?)').run(guidCreate, JSON.stringify(createMessage));
  db.prepare('insert or replace into messages(guid, message) values(?, ?)').run(guidNote, JSON.stringify(noteMessage));

  return createMessage;
}

/**
 * Sends a create message to all followers of an account.
 *
 * @param {string} text - The text of the message.
 * @param {string} name - The name of the account.
 * @param {string} domain - The domain of the account.
 * @param {Express.request} req - The request object.
 * @param {Express.response} res - The response object.
 * @return {Express.response} - The response JSON object.
 */
function sendCreateMessage(text, name, domain, req, res) {
  const db = req.app.get('db');
  const result = db.prepare('SELECT followers FROM accounts WHERE name = ?').get(`${name}@${domain}`);
  const followers = JSON.parse(result.followers);

  if (!followers) {
    return res.status(400).json({ msg: `No followers for account ${name}@${domain}` });
  }

  followers.forEach((follower) => {
    const inbox = `${follower}/inbox`;
    const myURL = new URL(follower);
    const targetDomain = myURL.host;
    const message = createMessage(text, name, domain, req, res, follower);
    signAndSend(message, name, domain, req, res, targetDomain, inbox);
  });

  return res.status(200).json({ msg: 'ok' });
}

module.exports = router;
